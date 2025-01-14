package main

import (
	"backend-deep-learning/database"
	"backend-deep-learning/route"

	"github.com/gofiber/fiber/v2"
)

func main() {
	app:= fiber.New()
	database.Database()
	route.UserRoute(app)
	app.Listen(":8000")
}
