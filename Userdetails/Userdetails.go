package Userdetails

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// describe user
type UserData struct {
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	PASSWORD      string             `json:"password" bson:"password"`
	EMAIL         string             `json:"email" bson:"email"`
	USERNAME      string             `json:"username" bson:"username"`
	FIRST_NAME    string             `json:"first_name" bson:"first_name"`
	LAST_NAME     string             `json:"last_name" bson:"last_name"`
	DATE_OF_BIRTH string             `json:"date_of_birth" bson:"date_of_birth"`
	BIO           string             `json:"bio" bson:"bio"`
	IsAdmin       bool               `json:"isAdmin,omitempty" bson:"isAdmin,omitempty"`
}

// describe credentilas for authentication via login
type Credentilas struct {
	PASSWORD string `json:"password" bson:"password"`
	EMAIL    string `json:"email" bson:"email"`
}

// Session represents a user session
type Session struct {
	ID       string             `bson:"_id"`
	USER_ID  primitive.ObjectID `json:"userid" bson:"_userid,omitempty"`
	CREATED  time.Time          `json:"created" bson:"created"`
	MODIFIED time.Time          `json:"modified" bson:"modified"`
}
