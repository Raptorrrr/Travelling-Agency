package models

import "gorm.io/gorm"

type Packages struct {
	gorm.Model
	Name           string
	Destination_Id uint
	Descriptions   string
	Image_url      string
	Price          int
	Capacity       int
}
