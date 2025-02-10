package controller

import (
	"context"
	"mime/multipart"
	"os"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
)

var (
	ctx = context.Background()
	cld *cloudinary.Cloudinary
)

func init() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	cloudinaryURL := os.Getenv("CLOUDINARY_URL")
	if cloudinaryURL == "" {
		panic("CLOUDINARY_URL not set in environment")
	}

	var err2 error
	cld, err2 = cloudinary.NewFromURL(cloudinaryURL)
	if err2 != nil {
		panic("Failed to initialize Cloudinary: " + err2.Error())
	}
}

// UploadFile uploads a file to Cloudinary
func UploadFile(file *multipart.FileHeader) (string, error) {
	// Open the file to be uploaded
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Upload file to Cloudinary
	uploadResult, err := cld.Upload.Upload(ctx, src, uploader.UploadParams{
		Folder: "go-uploads",
	})
	if err != nil {
		return "", err
	}

	return uploadResult.SecureURL, nil
}

// UploadHandler handles the file upload request
func UploadHandler(c *fiber.Ctx) error {
	// Check for token in headers
	token := c.Get("Authorization")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Missing authorization token",
		})
	}

	// Get the file from the form
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  false,
			"message": "Failed to get file from request",
		})
	}

	// Call the UploadFile function
	url, err := UploadFile(file)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  false,
			"message": "Failed to upload file to storage",
		})
	}

	// Return the URL of the uploaded file
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "File uploaded successfully",
		"status":  true,
		"url":     url,
	})
}
