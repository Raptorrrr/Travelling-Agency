package main

import (
	"login-jwt/config"
	"login-jwt/controllers"
	"login-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	config.LoadEnvVariables()
	config.ConnectToDb()
	config.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.SignUp)
	r.POST("/login", controllers.Login)
	r.GET("/validate", middleware.RequireAuth, controllers.GetUser)
	r.PUT("/edit-profile/:id", middleware.RequireAuth, controllers.UpdateUser)
	r.PUT("/change-password/:id", middleware.RequireAuth, controllers.ChangePassword)

	r.Run()
}
