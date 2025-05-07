package repositories

import (
	"davet.link/configs/configsdatabase"
	"davet.link/configs/configslog"
	"davet.link/models"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

type IAuthRepository interface {
	FindUserByAccount(account string) (*models.User, error)
	FindUserByID(id uint) (*models.User, error)
	UpdateUser(user *models.User) error
}

type AuthRepository struct {
	db *gorm.DB
}

func NewAuthRepository() IAuthRepository {
	return &AuthRepository{db: configsdatabase.GetDB()}
}

func (r *AuthRepository) executeQuery(query *gorm.DB, operation string, fields ...zap.Field) error {
	if err := query.Error; err != nil {
		fields = append(fields, zap.Error(err))
		configslog.Log.Error(operation+" hatası", fields...)
		return err
	}
	return nil
}

func (r *AuthRepository) findUser(query *gorm.DB, operation string, fields ...zap.Field) (*models.User, error) {
	var user models.User
	err := r.executeQuery(query.First(&user), operation, fields...)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepository) FindUserByAccount(account string) (*models.User, error) {
	return r.findUser(
		r.db.Where("account = ?", account),
		"Kullanıcı sorgulama (account)",
		zap.String("account", account),
	)
}

func (r *AuthRepository) FindUserByID(id uint) (*models.User, error) {
	return r.findUser(
		r.db.Where("id = ?", id),
		"Kullanıcı sorgulama (ID)",
		zap.Uint("user_id", id),
	)
}

func (r *AuthRepository) UpdateUser(user *models.User) error {
	return r.executeQuery(
		r.db.Save(user),
		"Kullanıcı güncelleme",
		zap.Uint("user_id", user.ID),
		zap.String("account", user.Account),
	)
}

var _ IAuthRepository = (*AuthRepository)(nil)
