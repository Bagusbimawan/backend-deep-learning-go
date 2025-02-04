package route

import (
	"backend-deep-learning/controller"

	"github.com/gofiber/fiber/v2"
)

func UserRoute(app *fiber.App) {
	api := app.Group("/api")
	api.Post("/register", controller.Register)
	api.Post("/upload", controller.UploadHandler)
	api.Post("/login", controller.Login)
	api.Post("/logout", controller.Logout)
	api.Get("/user/:id", controller.GetUserByID)
	api.Put("/user/:id", controller.UpdateUserByID)
	api.Delete("/user/:id", controller.DeleteUserByID)
}
