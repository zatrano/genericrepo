package services

import (
	"davet.link/configs/configslog"
	"davet.link/models"
	"davet.link/repositories"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type ServiceError string

func (e ServiceError) Error() string {
	return string(e)
}

const (
	ErrInvalidCredentials       ServiceError = "geçersiz kimlik bilgileri"
	ErrUserNotFound             ServiceError = "kullanıcı bulunamadı"
	ErrUserInactive             ServiceError = "kullanıcı aktif değil"
	ErrCurrentPasswordIncorrect ServiceError = "mevcut şifre hatalı"
	ErrPasswordTooShort         ServiceError = "yeni şifre en az 6 karakter olmalıdır"
	ErrPasswordSameAsOld        ServiceError = "yeni şifre mevcut şifre ile aynı olamaz"
	ErrAuthGeneric              ServiceError = "kimlik doğrulaması sırasında bir hata oluştu"
	ErrProfileGeneric           ServiceError = "profil bilgileri alınırken hata"
	ErrUpdatePasswordGeneric    ServiceError = "şifre güncellenirken bir hata oluştu"
	ErrHashingFailed            ServiceError = "yeni şifre oluşturulurken hata"
	ErrDatabaseUpdateFailed     ServiceError = "veritabanı güncellemesi başarısız oldu"
)

type IAuthService interface {
	Authenticate(account, password string) (*models.User, error)
	GetUserProfile(id uint) (*models.User, error)
	UpdatePassword(userID uint, currentPass, newPassword string) error
}

type AuthService struct {
	repo repositories.IAuthRepository
}

func NewAuthService() IAuthService {
	return &AuthService{repo: repositories.NewAuthRepository()}
}

func (s *AuthService) logAuthSuccess(account string, userID uint) {
	configslog.Log.Info("Kimlik doğrulama başarılı",
		zap.String("account", account),
		zap.Uint("user_id", userID),
	)
}

func (s *AuthService) logDBError(action string, err error, fields ...zap.Field) {
	fields = append(fields, zap.Error(err))
	configslog.Log.Error(action+" hatası (DB)", fields...)
}

func (s *AuthService) logWarn(action string, fields ...zap.Field) {
	configslog.Log.Warn(action+" başarısız", fields...)
}

func (s *AuthService) getUserByAccount(account string) (*models.User, error) {
	user, err := s.repo.FindUserByAccount(account)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logWarn("Kullanıcı bulunamadı", zap.String("account", account))
			return nil, ErrUserNotFound
		}
		s.logDBError("Kullanıcı sorgulama", err, zap.String("account", account))
		return nil, ErrAuthGeneric
	}
	return user, nil
}

func (s *AuthService) getUserByID(id uint) (*models.User, error) {
	user, err := s.repo.FindUserByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			s.logWarn("Kullanıcı bulunamadı", zap.Uint("user_id", id))
			return nil, ErrUserNotFound
		}
		s.logDBError("Kullanıcı sorgulama", err, zap.Uint("user_id", id))
		return nil, ErrProfileGeneric
	}
	return user, nil
}

func (s *AuthService) comparePasswords(hashedPassword, plainPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

func (s *AuthService) hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (s *AuthService) Authenticate(account, password string) (*models.User, error) {
	user, err := s.getUserByAccount(account)
	if err != nil {
		return nil, err
	}

	if !user.Status {
		s.logWarn("Kullanıcı aktif değil",
			zap.String("account", account),
			zap.Uint("user_id", user.ID),
		)
		return nil, ErrUserInactive
	}

	if err := s.comparePasswords(user.Password, password); err != nil {
		s.logWarn("Geçersiz parola",
			zap.String("account", account),
			zap.Uint("user_id", user.ID),
		)
		return nil, ErrInvalidCredentials
	}

	s.logAuthSuccess(account, user.ID)
	return user, nil
}

func (s *AuthService) GetUserProfile(id uint) (*models.User, error) {
	return s.getUserByID(id)
}

func (s *AuthService) UpdatePassword(userID uint, currentPass, newPassword string) error {
	user, err := s.getUserByID(userID)
	if err != nil {
		return err
	}

	if err := s.comparePasswords(user.Password, currentPass); err != nil {
		s.logWarn("Mevcut parola hatalı", zap.Uint("user_id", userID))
		return ErrCurrentPasswordIncorrect
	}

	if len(newPassword) < 6 {
		s.logWarn("Yeni parola çok kısa", zap.Uint("user_id", userID))
		return ErrPasswordTooShort
	}

	if currentPass == newPassword {
		s.logWarn("Yeni parola eskiyle aynı", zap.Uint("user_id", userID))
		return ErrPasswordSameAsOld
	}

	hashedPassword, err := s.hashPassword(newPassword)
	if err != nil {
		s.logDBError("Parola hashleme", err, zap.Uint("user_id", userID))
		return ErrHashingFailed
	}

	user.Password = hashedPassword
	if err := s.repo.UpdateUser(user); err != nil {
		s.logDBError("Kullanıcı güncelleme", err, zap.Uint("user_id", userID))
		return ErrDatabaseUpdateFailed
	}

	configslog.Log.Info("Parola başarıyla güncellendi", zap.Uint("user_id", userID))
	return nil
}

var _ IAuthService = (*AuthService)(nil)
