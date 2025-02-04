package controller

import (
	"context"
	"mime/multipart"

	"github.com/cloudinary/cloudinary-go/v2"
	"github.com/cloudinary/cloudinary-go/v2/api/uploader"
	"github.com/gofiber/fiber/v2"
)

var (
	ctx = context.Background()
	cld *cloudinary.Cloudinary
)

func init() {
	cld, _ = cloudinary.NewFromURL("cloudinary://771751577675731:H2stYwBW_gmdVXz6GAhrUzuarfg@dicczwwuo")
}

// UploadFile mengunggah file ke Cloudinary
func UploadFile(file *multipart.FileHeader) (string, error) {
	// Buka file yang akan diupload
	src, err := file.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	// Upload file ke Cloudinary
	uploadResult, err := cld.Upload.Upload(ctx, src, uploader.UploadParams{
		Folder: "go-uploads", // Folder di Cloudinary
	})
	if err != nil {
		return "", err
	}

	return uploadResult.SecureURL, nil
}

// UploadHandler handles the file upload request
func UploadHandler(c *fiber.Ctx) error {
	// Get the file from the form
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "status":false,
            "message":"failed get file ",

        })
	}

	// Call the UploadFile function
	url, err := UploadFile(file)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "status":false,
            "message":"failed upload file",
        })
	}

	// Return the URL of the uploaded file
	return c.JSON(fiber.Map{
        "message":"upload succes",
        "status":true,
        "url": url})
}
