package main

import (
	"backend-deep-learning/database"
	"backend-deep-learning/route"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Allow requests from any origin
		AllowHeaders: "origin, content-type, accept",
	}))

	database.Database()
	route.UserRoute(app)
	app.Listen(":8000")
}
