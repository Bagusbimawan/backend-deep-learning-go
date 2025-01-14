package route

import (
	"backend-deep-learning/controller"

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	api := app.Group("/api")
	api.Post("/register", controller.Register)
	api.Post("/login", controller.Login)
}
