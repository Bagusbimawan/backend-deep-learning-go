package controller

import (
	"backend-deep-learning/database"
	"backend-deep-learning/model"
	"strings"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *fiber.Ctx) error {
	var user model.User
	if err := c.BodyParser(&user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Check if username contains spaces
	if strings.Contains(user.Username, " ") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Username cannot contain spaces",
		})
	}

	// Check if password is 8 digits
	if len(user.Password) != 8 || len(user.Password) > 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password and username must be exactly 8 digits",
		})
	}

	// Hash the password before checking uniqueness
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to hash password",
		})
	}
	user.Password = string(hashedPassword)

	var existingUser model.User
	if err := database.DB.Where("password = ?", user.Password).First(&existingUser).Error; err == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password must be unique",
		})
	}

	database.DB.Create(&user)
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "User created successfully",
		"status":  fiber.StatusOK,
		"data":    user,
	})
}

func Login(c *fiber.Ctx) error {
	var loginRequest model.User
	if err := c.BodyParser(&loginRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	var user model.User
	if err := database.DB.Where("username = ?", loginRequest.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid username or password",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid username or password",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Login successful",
		"status":  fiber.StatusOK,
		"data":    user,
	})
}
