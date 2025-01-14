package database

import (
	"backend-deep-learning/model"
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB
func Database(){
	dsn := "host=localhost user=postgres password=123456 dbname=deep-learning port=5432 sslmode=disable "
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if  err !=  nil {
		fmt.Println("Error connecting to database:", err)
	}
	db.AutoMigrate(&model.User{})
	fmt.Println("Database migrated")
	fmt.Println("Connected to database")
	DB = db
}