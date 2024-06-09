package controllers

import (
	"login-jwt/config"
	"login-jwt/models"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func CreateDestination(c *gin.Context) {
	var destination models.Destinations
	user, _ := c.Get("user")

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

	err := c.ShouldBindJSON(&destination)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid destinations",
		})
		return
	}

	result := config.DB.Create(&destination)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create destinations",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "destinations created",
	})
}

func DeleteDestination(c *gin.Context) {
	var destination models.Destinations
	user, _ := c.Get("user")

	id, _ := strconv.Atoi(c.Param("id"))

	if !user.(models.User).IsLogin {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "please login first",
		})
		return
	}

	config.DB.First(&destination, id)
	if destination.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "destinations not found",
		})
	}

	if user.(models.User).Role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"message": "user unauthorized",
		})
		return
	}

	config.DB.Unscoped().Delete(&destination)
	c.JSON(http.StatusOK, gin.H{
		"message": "destination deleted",
	})
}

func GetAllDestination(c *gin.Context) {
	var destination []models.Destinations
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

	result := config.DB.Find(&destination)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "error retrieving users",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"destination": destination,
	})
}
