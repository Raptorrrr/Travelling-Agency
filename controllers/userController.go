package controllers

import (
	"login-jwt/config"
	"login-jwt/models"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	var user models.User
	// get the email , password , and name
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}

	// hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid to hash Password",
		})
		return
	}

	user.Password = string(hash)

	// create a user
	result := config.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func Login(c *gin.Context) {
	var user models.User
	var login struct {
		Email    string
		Password string
	}

	if c.Bind(&login) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	config.DB.First(&user, "email = ?", login.Email)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}

	// compare hash password
	if !comparePassword([]byte(user.Password), []byte(login.Password)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Email or Password",
		})
		return
	}

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid to create Token",
		})
		return
	}

	// send it back
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func GetUser(c *gin.Context) {

	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func UpdateUser(c *gin.Context) {
	var user models.User

	userr, _ := c.Get("user")
	id, _ := strconv.Atoi(c.Param("id"))

	// check if id token match with id
	if !validateId(id, int(userr.(models.User).ID)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found",
		})
		return
	}

	// get data from database
	config.DB.First(&user, id)

	// get request json
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid Input",
		})
		return
	}

	// update database
	config.DB.Model(&user).Updates(models.User{Name: user.Name, Email: user.Email})

	c.JSON(http.StatusOK, gin.H{
		"message": "Profile update success",
	})
}

func ChangePassword(c *gin.Context) {
	var user models.User
	var changePassword struct {
		OldPassword string
		NewPassword string
	}

	userr, _ := c.Get("user")
	id, _ := strconv.Atoi(c.Param("id"))

	// get data from database
	config.DB.First(&user, id)

	// check if id token match with id and find user by id in database
	if !validateId(id, int(userr.(models.User).ID)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User not found",
		})
		return
	}

	// get request json
	if c.Bind(&changePassword) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input",
		})
		return
	}

	// check old password with password in database
	if !comparePassword([]byte(user.Password), []byte(changePassword.OldPassword)) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid current password",
		})
		return
	}

	// hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(changePassword.NewPassword), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid to hash Password",
		})
		return
	}

	// update password
	config.DB.Model(&user).Updates(models.User{Password: string(hash)})

	c.JSON(http.StatusOK, gin.H{
		"message": "password change success",
	})

}

func validateId(id int, idToken int) bool {
	var user models.User

	config.DB.First(&user, id)
	if user.ID != 0 && idToken == id {
		return true
	} else {
		return false
	}
}

func comparePassword(hash []byte, password []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, password)
	return err == nil
}
