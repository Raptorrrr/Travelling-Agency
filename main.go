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
	r.GET("/logout", middleware.RequireAuth, controllers.Logout)
	r.DELETE("/delete/:id", middleware.RequireAuth, controllers.DeleteUser)
	r.GET("/users", middleware.RequireAuth, controllers.GetAllUser)

	r.POST("/create-destination", middleware.RequireAuth, controllers.CreateDestination)
	r.DELETE("/destination/delete/:id", middleware.RequireAuth, controllers.DeleteDestination)
	r.GET("/destinations", middleware.RequireAuth, controllers.GetAllDestination)

	r.POST("/:destinations/create-package", middleware.RequireAuth, controllers.CreatePackage)
	r.PUT("/:destinations/:id", middleware.RequireAuth, controllers.EditPackage)
	r.DELETE("/:destinations/:id", middleware.RequireAuth, controllers.DeletePackage)
	r.GET("/packages/:destinations", middleware.RequireAuth, controllers.GetAllPackageByCity)
	r.GET("/packages", middleware.RequireAuth, controllers.GetAllPackage)

	r.Run()
}
