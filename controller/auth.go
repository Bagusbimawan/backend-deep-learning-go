package controller

import (
	"backend-deep-learning/database"
	"backend-deep-learning/model"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
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
			"message": "Username cannot contain spaces",
		})
	}

	// Check if password length is at least 8 characters
	if len(user.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Password must be at least 8 characters",
		})
	}

	// Hash the password before checking uniqueness
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to encrypt password",
		})
	}
	user.Password = string(hashedPassword)

	var existingUser model.User
	if err := database.DB.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Username is already taken",
		})
	}

	if err := database.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to create user",
		})
	}

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

	// Validate username
	if loginRequest.Username == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Username cannot be empty",
		})
	}

	if strings.Contains(loginRequest.Username, " ") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Username cannot contain spaces",
		})
	}

	// Validate password
	if loginRequest.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Password cannot be empty",
		})
	}

	if len(loginRequest.Password) < 8 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Password must be at least 8 characters",
		})
	}

	var user model.User
	if err := database.DB.Where("username = ?", loginRequest.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "User not found",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginRequest.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid username or password",
		})
	}

	// Generate JWT token
	claims := jwt.MapClaims{
		"id":       user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Use a secure secret key - in production this should be in environment variables
	secretKey := []byte("bagus")

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate token",
		})
	}

	// Save token and expiry time to database
	tokenExpiry := time.Now().Add(time.Hour * 1)
	user.Token = tokenString
	user.TokenExpiry = tokenExpiry
	if err := database.DB.Model(&user).Updates(map[string]interface{}{
		"token":        tokenString,
		"token_expiry": tokenExpiry,
	}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to save token to database",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Login successful",
		"status":  fiber.StatusOK,
		"data":    user,
	})
}

func Logout(c *fiber.Ctx) error {
	// Get token from header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "No token provided",
		})
	}

	// Remove Bearer prefix
	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("bagus"), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"message": "Invalid token claims",
		})
	}

	userID := claims["id"].(float64)

	// Find user and validate token
	var user model.User
	if err := database.DB.Where("id = ? AND token = ?", uint(userID), tokenString).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
		})
	}

	if time.Now().After(user.TokenExpiry) {
		// Clear expired token
		if err := database.DB.Model(&user).Updates(map[string]interface{}{
			"token":        "",
			"token_expiry": time.Time{},
		}).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to clear expired token",
			})
		}

		// Clear cookie and header
		c.ClearCookie("jwt")
		c.Request().Header.Del("Authorization")

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token has expired",
		})
	}

	// Clear token in database
	if err := database.DB.Model(&user).Updates(map[string]interface{}{
		"token":        "",
		"token_expiry": time.Time{},
	}).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to clear token in database",
		})
	}

	// Clear the JWT token cookie
	c.ClearCookie("jwt")

	// Remove the token from the request context
	c.Locals("user", nil)

	// Clear Authorization header
	c.Request().Header.Del("Authorization")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Logout successful",
		"status":  fiber.StatusOK,
	})
}
