package models

import "gorm.io/gorm"

type Destinations struct {
	gorm.Model
	Country string     `gorm:"not null"`
	City    string     `gorm:"unique;not null"`
	Package []Packages `gorm:"foreignKey:Destination_Id"`
}
