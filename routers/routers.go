package routers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	//"encoding/json"

	//"time"

	"github.com/Sachingeek125/GolangAuth/Userdetails"
	"github.com/Sachingeek125/GolangAuth/db"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	//"github.com/jackyzha0/go-auth-w-mongo/db"
)

var Sessionduration = time.Hour * 24
var store = sessions.NewCookieStore([]byte("secert-key"))

func Routers() *mux.Router {
	r := mux.NewRouter().StrictSlash(true)

	return r
}

// Crud endpoint for creating a user
func CreateUser(w http.ResponseWriter, r *http.Request) {
	// decode json to user struct

	var user Userdetails.UserData
	err := json.NewDecoder(r.Body).Decode(&user)

	// error handling if error occurs
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db := db.Client.Database("exampleDB")
	collection2 := db.Collection("users")

	// Retrive the latest session into database
	session, err := GetRecentSession(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// decoding the recent user from user_id of session
	var recentuser Userdetails.UserData
	err = collection2.FindOne(context.Background(), bson.M{"_id": session.USER_ID}).Decode(&recentuser)

	// if recentuser is not admin then restrict him from adding a user
	if !recentuser.IsAdmin {
		http.Error(w, "You are not admin,so you're not allowed to add users", http.StatusBadRequest)
		return
	}

	// validating user data
	if user.EMAIL == "" || user.PASSWORD == "" {
		http.Error(w, "Email or password missing.", http.StatusBadRequest)
		return
	}

	// checking if that email already exists into database or not

	count, err := collection2.CountDocuments(context.Background(), bson.M{"email": user.EMAIL})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Error(w, "Email already exist.", http.StatusBadRequest)
		return
	}

	// hashing password for the purpose of security
	hash, err := bcrypt.GenerateFromPassword([]byte(user.PASSWORD), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	user.PASSWORD = string(hash)

	// inserting the user into database
	result, err := collection2.InsertOne(context.Background(), user)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// retriving the inserted id of result
	id := result.InsertedID.(primitive.ObjectID).Hex()
	// set the content type header and return newly created as a json
	w.Header().Set("content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	response := make(map[string]interface{})
	response["message"] = "User Created Sucessfully."
	response["id"] = id
	json.NewEncoder(w).Encode(response)

}

// Update end point for updating details of user by id if exists(any user's details can be only updated by a that user itself or admin only)
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	// Get the id parameter from URL
	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	db := db.Client.Database("exampleDB")
	collection := db.Collection("users")

	// Getting the recent session and detect the recentuser based upon that
	session, err := GetRecentSession(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var recentuser Userdetails.UserData
	err = collection.FindOne(context.Background(), bson.M{"_id": session.USER_ID}).Decode(&recentuser)
	var user Userdetails.UserData

	// if recentuser is not the user itself or not an admin then restrict him there
	if recentuser.ID != id && !recentuser.IsAdmin {
		http.Error(w, "Forbidden", http.StatusBadRequest)
		return

	}

	// decode the JSON return into user struct
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.ID = id

	// validate user data
	if user.EMAIL == "" || user.PASSWORD == "" {
		http.Error(w, "Email or password missing.", http.StatusBadRequest)
		return
	}
	// if non-admin user has created himself admin then restrict him
	if recentuser.ID == id && !recentuser.IsAdmin {
		if user.IsAdmin {
			http.Error(w, "You Can't make yourself admin", http.StatusUnauthorized)
			return
		}
	}
	// replacing the old user info with new ones
	result, err := collection.ReplaceOne(context.Background(), bson.M{"_id": id}, user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check if user was found and updated or not
	if result.MatchedCount == 0 {
		http.Error(w, "User not exists.", http.StatusNotFound)
		return
	}

	// sets the response message
	response := make(map[string]interface{})
	response["message"] = "User Updated sucessfully."
	response["id"] = id.Hex()
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

// delete endpoint for deleting user by id(admin can delete anyuser but a user can delete only his)
func DeleteUser(w http.ResponseWriter, r *http.Request) {

	// Get the id parameter from URL
	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	db := db.Client.Database("exampleDB")
	collection := db.Collection("users")

	// retriving the recent sessions and detecting recentuser based upon that
	session, err := GetRecentSession(db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// finding recentuser and deleteduser into mongodb
	var recentuser Userdetails.UserData
	var deleteduser Userdetails.UserData
	err = collection.FindOne(context.Background(), bson.M{"_id": session.USER_ID}).Decode(&recentuser)
	err = collection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&deleteduser)

	// if deleteduser is not recentuser(non-admin) then restrict him
	if recentuser.ID != id && !recentuser.IsAdmin {
		http.Error(w, "You're not admin so You Can't delete other users", http.StatusBadRequest)
		return

	}
	// if non-admin tries to delete adminuser then restrict him
	if deleteduser.IsAdmin && !recentuser.IsAdmin {
		http.Error(w, "You can not delete an admin", http.StatusBadRequest)
		return
	}

	// if admin tries to delete himself then also restrict him
	if deleteduser.IsAdmin && recentuser.IsAdmin && recentuser.ID == deleteduser.ID {
		http.Error(w, "You can not delete yourself", http.StatusBadRequest)
		return
	}

	// deleting user from database
	result, err := collection.DeleteOne(context.Background(), bson.M{"_id": id})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check if user was deleted or not
	if result.DeletedCount == 0 {
		http.Error(w, "User does not exists.", http.StatusNotFound)
		return
	}

	// set the response message and return deleted user id
	response := make(map[string]interface{})
	response["message"] = "User Deleted sucessfully."
	response["id"] = id.Hex()
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

}

// GetbyID endpoint returns the user by given id
func GetUserByID(w http.ResponseWriter, r *http.Request) {
	// Get the id parameter from URL
	params := mux.Vars(r)
	id, err := primitive.ObjectIDFromHex(params["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var user Userdetails.UserData
	db := db.Client.Database("exampleDB")
	collection := db.Collection("users")

	// retrive the user by given id from database
	err = collection.FindOne(context.Background(), bson.M{"_id": id}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			http.Error(w, "User couldn't find.", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusUnauthorized)

		}
		return
	}
	// set the content-type and return user as a json
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

}

// Getall endpoint returns all the users into database irrespective of ids
func GetAllUsers(w http.ResponseWriter, r *http.Request) {

	var user Userdetails.UserData
	db := db.Client.Database("exampleDB")
	collection := db.Collection("users")

	// retriving latest session for detecting user
	session, err := GetRecentSession(db)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// fmt.Println("Here Below: ")
	// if session is null then return from here
	if session == nil {
		fmt.Println("session is null")
		return
	}
	// fmt.Println(session.USER_ID)
	collection2 := db.Collection("users")

	// retrive the user by recent session user_id
	err = collection2.FindOne(context.Background(), bson.M{"_id": session.USER_ID}).Decode(&user)
	if err != nil {
		// if no documents found then give error
		if errors.Is(err, mongo.ErrNoDocuments) {
			http.Error(w, "User couldn't find.", http.StatusNotFound)
		} else {
			http.Error(w, err.Error(), http.StatusUnauthorized)

		}
		return
	}
	// if retrived user is not admin then show only his details to him
	if !user.IsAdmin {
		// finding a user into database and decode it
		err = collection2.FindOne(context.Background(), bson.M{"_id": session.USER_ID}).Decode(&user)
		if err != nil {
			if errors.Is(err, mongo.ErrNoDocuments) {
				http.Error(w, "User couldn't find.", http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusUnauthorized)

			}
			return
		}
		// set the content-type and return user as a json
		w.Header().Set("content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		return

	}

	// if the retrived user is admin then show him details of all users

	// find all users into database
	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	// intalize a slice to store users
	var data []Userdetails.UserData

	// iterate over cursor and decode each document into database
	for cursor.Next(context.Background()) {
		var user Userdetails.UserData
		if err := cursor.Decode(&user); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data = append(data, user)

	}
	// check if cursor has any error or it has been exhausted
	if err := cursor.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// set the response header and return the user as a JSON
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(data)

}

// This function returns the latest modified/created session from sessions collection
func GetRecentSession(db *mongo.Database) (*Userdetails.Session, error) {

	col := db.Client().Database("exampleDB").Collection("sessions")

	// checking if collection is null or not
	if col == nil {
		return nil, errors.New("Collection is Nil")
	}

	// Find session with latest modified time stamp and sort it
	options := options.FindOne().SetSort(bson.D{{Key: "modified", Value: -1}})
	var session Userdetails.Session
	// find session and decode properties of that particular session
	err := col.FindOne(context.Background(), bson.M{}, options).Decode(&session)

	// checking if there are any errors encoutered or not
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("No Matching document found: %w", err)
		}
		log.Println(err)
		return nil, err
	}
	// if no user is associated with retrived session then give error that session is null
	if session.USER_ID == primitive.NilObjectID {
		return nil, errors.New("Session is NULL")

	}
	return &session, nil

}

// creates a new user session into mongodb database
func CreateSession(db *mongo.Database, userobjID primitive.ObjectID) (*Userdetails.Session, error) {

	collection := db.Collection("sessions")

	// creating new session and inserting sessions info into session
	session := &Userdetails.Session{
		ID:       primitive.NewObjectID().Hex(),
		USER_ID:  userobjID,
		CREATED:  time.Now(),
		MODIFIED: time.Now(),
	}

	// userObjID, err := primitive.ObjectIDFromHex(userID)
	// if err != nil {
	// 	return nil, err
	// }

	// inserting the session into session collection
	result, err := collection.InsertOne(context.Background(), session)
	fmt.Println(result)
	if err != nil {
		return nil, err
	}

	return session, nil
}

// getsession retrives a session from database from sessionID
func GetSession(db *mongo.Database, SessionID string) (*Userdetails.Session, error) {
	var session Userdetails.Session
	collection := db.Collection("sessions")
	// find the session into database from inserted sessin-id and returning it if sucess
	err := collection.FindOne(context.Background(), bson.M{"_id": SessionID}).Decode(&session)
	if err != nil {
		return nil, err
	}
	session.MODIFIED = time.Now()
	return &session, nil
}

// deletesession deletes a session from database
func DeleteSession(db *mongo.Database, SessionID string) error {
	collection := db.Collection("sessions")
	// delete session ID entry from given the sessionid
	_, err := collection.DeleteOne(context.Background(), bson.M{"_id": SessionID})
	return err

}

// Register creates a new user in the database and stores a session into database
func Register(w http.ResponseWriter, r *http.Request) {
	var user Userdetails.UserData
	// decoding json body of newuser
	newUser := new(Userdetails.UserData)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&user)

	// error handling if it happens
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// reads and parse the request body
	parseFormErr := r.ParseForm()
	if parseFormErr != nil {
		// If the structure of the body is wrong, return an HTTP error
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "error: %v", parseFormErr)
		return
	}
	db := db.Client.Database("exampleDB")
	collection := db.Collection("users")

	// counting the documents into users collection
	total, err := collection.CountDocuments(context.Background(), bson.D{})

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// if there are no users there then make this newuser an admin by default
	if total == 0 {
		// Decode form values into the newUser struct

		newUser = &Userdetails.UserData{
			BIO:           user.BIO,
			FIRST_NAME:    user.FIRST_NAME,
			LAST_NAME:     user.LAST_NAME,
			USERNAME:      user.USERNAME,
			DATE_OF_BIRTH: user.DATE_OF_BIRTH,
			IsAdmin:       true,
		}

	} else {

		// else don't make them admin

		// Decode form values into the newUser struct

		newUser = &Userdetails.UserData{
			BIO:           user.BIO,
			FIRST_NAME:    user.FIRST_NAME,
			LAST_NAME:     user.LAST_NAME,
			USERNAME:      user.USERNAME,
			DATE_OF_BIRTH: user.DATE_OF_BIRTH,
			IsAdmin:       false,
		}

	}
	// inserting email and password into newuser from request body
	newUser.EMAIL = user.EMAIL
	newUser.PASSWORD = user.PASSWORD

	// validating for email and password
	if newUser.EMAIL == "" || newUser.PASSWORD == "" {
		fmt.Println(newUser.EMAIL)
		fmt.Println(newUser.PASSWORD)
		http.Error(w, "Email and password both are required", http.StatusBadRequest)
		return
	}

	// check if user already exists

	fmt.Println(newUser.EMAIL)
	count, err := collection.CountDocuments(context.Background(), bson.M{"email": newUser.EMAIL})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if count > 0 {
		http.Error(w, "Email already exist.", http.StatusBadRequest)
		return
	}

	// encrypt the password using bcrypt for security reasons
	hash, err := bcrypt.GenerateFromPassword([]byte(newUser.PASSWORD), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newUser.PASSWORD = string(hash)

	// inserting newuser into database
	// _, err = collection.InsertOne(context.Background(), newUser)
	result, err := collection.InsertOne(context.Background(), newUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	newUser.ID = result.InsertedID.(primitive.ObjectID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Printf("User ID: ")
	fmt.Println(newUser.ID)

	// create a new session for user
	id := newUser.ID.Hex()
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		// handle the error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := CreateSession(db, objID)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// set session header for user

	w.Header().Set("Session-ID", session.ID)
	// w.Header().Set("User-ID", newUser.ID.Hex())
	// w.Write([]byte("User Created"))
	log.Printf("Created new user with email %v", newUser.EMAIL)
	fmt.Fprintf(w, "User Created with %s", newUser.USERNAME)
	fmt.Printf(newUser.USERNAME)
	w.WriteHeader(http.StatusOK)
	log.Printf("User created with: ")
	log.Printf(newUser.EMAIL)
	log.Printf(" and User is %v", newUser.IsAdmin)

}

func Login(w http.ResponseWriter, r *http.Request) {

	// returns the first value of specified key from parsed form
	email := r.FormValue("email")
	password := r.FormValue("password")
	// cred := new(Userdetails.Credentilas)
	// decoder := json.NewDecoder(r.Body)
	// err := decoder.Decode(&cred)

	// fmt.Println(email)
	// fmt.Println(password)

	// if email and password fields are empty then restricts it
	if email == "" || password == "" {
		http.Error(w, "Email and password both are required", http.StatusBadRequest)
		return
	}

	db := db.Client.Database("exampleDB")

	coll := db.Collection("users")
	var user Userdetails.UserData

	// finding a a entered email and decoding user if its exists
	err := coll.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)

	if err != nil {

		if err == mongo.ErrNoDocuments {
			http.Error(w, "No User exists", http.StatusUnauthorized)
			return
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)

		}
		return
	}

	// check password
	err = bcrypt.CompareHashAndPassword([]byte(user.PASSWORD), []byte(password))

	if err != nil {
		http.Error(w, "Invalid password and email", http.StatusUnauthorized)
		return
	}

	// retriving objectID from id
	id := user.ID.Hex()
	objID, err := primitive.ObjectIDFromHex(id)

	if err != nil {
		// handle the error
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// create a new session
	session, err := CreateSession(db, objID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// set session header
	w.Header().Set("Session-ID", session.ID)
	fmt.Fprintf(w, "Your Session-ID %s", session.ID)
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "Logged in as %s", user.USERNAME)

}

// Logout handlers Logout user and deletes it's session
func Logout(w http.ResponseWriter, r *http.Request) {
	// Getting session-id from session header
	sessionID := r.Header.Get("Session-ID")
	fmt.Println(sessionID)
	// if sessionID is empty then restricts it
	if sessionID == "" {
		http.Error(w, "Session-ID required", http.StatusBadRequest)
		return
	}
	db := db.Client.Database("exampleDB")

	// retrive the session from sessionID
	_, err := GetSession(db, sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// delete the session
	err = DeleteSession(db, sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// printing the mesage when session is deleted
	fmt.Fprintf(w, "Session %s deleted", sessionID)

}
