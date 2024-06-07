package models

import "gorm.io/gorm"

type Destinations struct {
	gorm.Model
	Country string
	City    string
}
