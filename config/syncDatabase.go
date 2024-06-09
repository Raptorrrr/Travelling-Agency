package config

import "login-jwt/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.Destinations{})
	DB.AutoMigrate(&models.Packages{})
}
