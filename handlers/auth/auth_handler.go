package handlers

import (
	"net/http"

	"davet.link/configs/configslog"
	"davet.link/configs/configssession"
	"davet.link/models"
	"davet.link/pkg/flashmessages"
	"davet.link/pkg/renderer"
	"davet.link/services"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type AuthHandler struct {
	service services.IAuthService
}

func NewAuthHandler() *AuthHandler {
	return &AuthHandler{service: services.NewAuthService()}
}

func (h *AuthHandler) handleError(c *fiber.Ctx, err error, userID uint, account string, action string) error {
	var errMsg string
	flashKey := flashmessages.FlashErrorKey
	redirectTarget := "/auth/login"
	logoutUser := false

	switch err {
	case services.ErrInvalidCredentials:
		errMsg = "Kullanıcı adı veya şifre hatalı."
	case services.ErrUserInactive:
		errMsg = "Hesabınız aktif değil. Lütfen yöneticinizle iletişime geçin."
	case services.ErrUserNotFound:
		errMsg = "Kullanıcı bulunamadı, lütfen tekrar giriş yapın."
		logoutUser = true
		configslog.Log.Warn(action+": Kullanıcı bulunamadı", zap.Uint("user_id", userID))
	case services.ErrCurrentPasswordIncorrect:
		errMsg = "Mevcut şifreniz hatalı."
		redirectTarget = "/auth/profile"
	case services.ErrPasswordTooShort, services.ErrPasswordSameAsOld:
		errMsg = err.Error()
		redirectTarget = "/auth/profile"
	default:
		errMsg = "İşlem sırasında bir sorun oluştu. Lütfen tekrar deneyin."
		configslog.Log.Error(action+": Beklenmeyen hata",
			zap.Uint("user_id", userID),
			zap.String("account", account),
			zap.Error(err))
	}

	if logoutUser {
		h.destroySession(c)
	}

	_ = flashmessages.SetFlashMessage(c, flashKey, errMsg)
	return c.Redirect(redirectTarget, fiber.StatusSeeOther)
}

func (h *AuthHandler) getSessionUser(c *fiber.Ctx) (uint, error) {
	if userID, ok := c.Locals("userID").(uint); ok {
		return userID, nil
	}

	sess, err := configssession.SessionStart(c)
	if err != nil {
		return 0, err
	}

	userIDValue := sess.Get("user_id")
	switch v := userIDValue.(type) {
	case uint:
		return v, nil
	case int:
		return uint(v), nil
	case float64:
		return uint(v), nil
	default:
		return 0, fiber.ErrUnauthorized
	}
}

func (h *AuthHandler) destroySession(c *fiber.Ctx) {
	sess, err := configssession.SessionStart(c)
	if err != nil {
		configslog.Log.Warn("Oturum yok edilemedi (zaten yok olabilir)", zap.Error(err))
		return
	}
	if err := sess.Destroy(); err != nil {
		configslog.Log.Error("Oturum yok edilemedi", zap.Error(err))
	}
}

func (h *AuthHandler) createUserSession(c *fiber.Ctx, user *models.User) error {
	sess, err := configssession.SessionStart(c)
	if err != nil {
		return err
	}

	sess.Set("user_id", user.ID)
	sess.Set("user_type", string(user.Type))
	sess.Set("user_status", user.Status)
	sess.Set("user_name", user.Name)

	if err := sess.Save(); err != nil {
		return err
	}

	return nil
}

func (h *AuthHandler) ShowLogin(c *fiber.Ctx) error {
	mapData := fiber.Map{
		"Title": "Giriş",
	}
	return renderer.Render(c, "auth/login", "layouts/auth", mapData, http.StatusOK)
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var request struct {
		Account  string `form:"account"`
		Password string `form:"password"`
	}

	if err := c.BodyParser(&request); err != nil {
		configslog.SLog.Warnf("Login isteği ayrıştırılamadı: %v", err)
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Lütfen hesap adı ve şifre alanlarını doldurun.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	if request.Account == "" || request.Password == "" {
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Lütfen hesap adı ve şifre alanlarını doldurun.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	user, err := h.service.Authenticate(request.Account, request.Password)
	if err != nil {
		return h.handleError(c, err, 0, request.Account, "Login")
	}

	if err := h.createUserSession(c, user); err != nil {
		configslog.Log.Error("Oturum oluşturulamadı (Login)",
			zap.Uint("user_id", user.ID),
			zap.String("account", user.Account),
			zap.Error(err))
		return h.handleError(c, fiber.ErrInternalServerError, user.ID, user.Account, "Login")
	}

	var redirectURL string
	switch user.Type {
	case models.Panel:
		redirectURL = "/panel/home"
	case models.Dashboard:
		redirectURL = "/dashboard/home"
	default:
		h.destroySession(c)
		configslog.Log.Error("Geçersiz kullanıcı tipi",
			zap.Uint("user_id", user.ID),
			zap.String("account", user.Account),
			zap.String("type", string(user.Type)))
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Hesabınız için tanımlanmış bir rol bulunamadı.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	_ = flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey, "Başarıyla giriş yapıldı.")
	return c.Redirect(redirectURL, fiber.StatusFound)
}

func (h *AuthHandler) Profile(c *fiber.Ctx) error {
	userID, err := h.getSessionUser(c)
	if err != nil {
		configslog.Log.Warn("Profil: Geçersiz oturum", zap.Error(err))
		h.destroySession(c)
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Geçersiz oturum, lütfen tekrar giriş yapın.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	user, err := h.service.GetUserProfile(userID)
	if err != nil {
		return h.handleError(c, err, userID, "", "Profil")
	}

	mapData := fiber.Map{
		"Title": "Profilim",
		"User":  user,
	}
	return renderer.Render(c, "auth/profile", "layouts/auth", mapData, http.StatusOK)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	h.destroySession(c)
	_ = flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey, "Başarıyla çıkış yapıldı.")
	return c.Redirect("/auth/login", fiber.StatusFound)
}

func (h *AuthHandler) UpdatePassword(c *fiber.Ctx) error {
	userID, err := h.getSessionUser(c)
	if err != nil {
		h.destroySession(c)
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Geçersiz oturum bilgisi, lütfen tekrar giriş yapın.")
		return c.Redirect("/auth/login", fiber.StatusSeeOther)
	}

	var request struct {
		CurrentPassword string `form:"current_password"`
		NewPassword     string `form:"new_password"`
		ConfirmPassword string `form:"confirm_password"`
	}

	if err := c.BodyParser(&request); err != nil {
		configslog.SLog.Warnf("Parola güncelleme isteği ayrıştırılamadı: %v", err)
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Lütfen tüm şifre alanlarını doldurun.")
		return c.Redirect("/auth/profile", fiber.StatusSeeOther)
	}

	if request.CurrentPassword == "" || request.NewPassword == "" || request.ConfirmPassword == "" {
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Lütfen tüm şifre alanlarını doldurun.")
		return c.Redirect("/auth/profile", fiber.StatusSeeOther)
	}

	if request.NewPassword != request.ConfirmPassword {
		_ = flashmessages.SetFlashMessage(c, flashmessages.FlashErrorKey, "Yeni şifreler uyuşmuyor.")
		return c.Redirect("/auth/profile", fiber.StatusSeeOther)
	}

	if err := h.service.UpdatePassword(userID, request.CurrentPassword, request.NewPassword); err != nil {
		return h.handleError(c, err, userID, "", "Parola Güncelleme")
	}

	h.destroySession(c)
	_ = flashmessages.SetFlashMessage(c, flashmessages.FlashSuccessKey, "Şifre başarıyla güncellendi. Lütfen yeni şifrenizle tekrar giriş yapın.")
	return c.Redirect("/auth/login", fiber.StatusFound)
}
