package controllers

import (
	"login-jwt/config"
	"login-jwt/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CreatePackage(c *gin.Context) {
	var pack models.Packages
	var destination models.Destinations
	user, _ := c.Get("user")

	name := c.Param("destinations")

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "user doesn't have permission access",
		})
		return
	}

	// check if destinations id is valid on database destinations
	config.DB.Where("city = ?", name).First(&destination)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Destinations not found",
		})
		return
	}

	err := c.ShouldBindJSON(&pack)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid pack",
		})
		return
	}

	// assign destination id
	pack.Destination_Id = destination.ID

	result := config.DB.Create(&pack)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create packages",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "destinations created",
	})
}

func EditPackage(c *gin.Context) {
	var pack models.Packages
	var destination models.Destinations

	user, _ := c.Get("user")

	city := c.Param("destinations")
	id := c.Param("id")

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "user doesn't have permission access",
		})
		return
	}

	config.DB.Where("city = ?", city).First(&destination)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Destinations city not found",
		})
		return
	}

	config.DB.Where("id = ?", id).First(&pack)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "package not found",
		})
		return
	}

	err := c.ShouldBindJSON(&pack)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Input",
		})
		return
	}

	config.DB.Model(&pack).Updates(models.Packages{
		Name:         pack.Name,
		Descriptions: pack.Descriptions,
		Image_url:    pack.Image_url,
		Price:        pack.Price,
		Capacity:     pack.Capacity})

	c.JSON(http.StatusOK, gin.H{
		"message": "Packages update successfull",
	})
}

func DeletePackage(c *gin.Context) {
	var pack models.Packages
	var destination models.Destinations

	user, _ := c.Get("user")

	city := c.Param("destinations")
	id := c.Param("id")

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "user doesn't have permission access",
		})
		return
	}

	config.DB.Where("city = ?", city).First(&destination)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Destinations city not found",
		})
		return
	}

	config.DB.Where("id = ?", id).First(&pack)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "package not found",
		})
		return
	}

	config.DB.Unscoped().Delete(&pack)

	c.JSON(http.StatusOK, gin.H{
		"message": "Packages delete successfull",
	})
}

func GetAllPackageByCity(c *gin.Context) {
	var destination models.Destinations
	var pack []models.Packages
	user, _ := c.Get("user")
	city := c.Param("destinations")

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "user doesn't have access",
		})
		return
	}

	config.DB.Where("city = ?", city).First(&destination)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Destinations city not found",
		})
		return
	}

	result := config.DB.Find(&pack, "destination_id", destination.ID)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "error retrieving packages",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"destination": pack,
	})
}

func GetAllPackage(c *gin.Context) {
	var pack []models.Packages
	user, _ := c.Get("user")

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "user doesn't have access",
		})
		return
	}

	result := config.DB.Find(&pack)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "error retrieving packages",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"destination": pack,
	})
}
