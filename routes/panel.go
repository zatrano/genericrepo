package routes

import (
	handlers "zatrano/handlers/panel"
	"zatrano/middlewares"
	"zatrano/models"

	"github.com/gofiber/fiber/v2"
)

func registerPanelRoutes(app *fiber.App) {
	panelGroup := app.Group("/panel")
	panelGroup.Use(
		middlewares.AuthMiddleware,
		middlewares.StatusMiddleware,
		middlewares.TypeMiddleware(models.Panel),
	)

	panelGroup.Get("/home", handlers.PanelHomeHandler)
}
