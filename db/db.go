package db

import (
	"context"
	"log"
	"time"

	"github.com/gorilla/sessions"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client
var Users *mongo.Collection
var store = sessions.NewCookieStore([]byte("secert-key"))

// func init() {
// 	//setup Mongo db client
// 	Client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://Sachin125:Btechict%40125@cluster0.spqnong.mongodb.net/?retryWrites=true&w=majority"))
// 	if err != nil {
// 		panic(err)
// 	}
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()
// 	err = Client.Connect(ctx)
// 	if err != nil {
// 		panic(err)
// 	}
// 	db = Client.Database("exampleDB")

// }

const (
	DB_LOCAL        = 0 // local mongo instance
	DB_LOCAL_W_AUTH = 1 // local mongo instance with credentials
	DB_ATLAS        = 2 // mongo atlas sharded instance
)

const DB_TYPE = DB_LOCAL

func init() {

	switch DB_TYPE {
	case DB_LOCAL:

		// Client is a connection to the given URI
		Client, _ = mongo.Connect(nil, options.Client().ApplyURI("mongodb+srv://Sachin125:Btechict%40125@cluster0.spqnong.mongodb.net/?retryWrites=true&w=majority").SetServerSelectionTimeout(5*time.Second))
		// Users is a new connection to Users Collection
		err := Client.Ping(context.Background(), nil)
		if err != nil {
			log.Fatal(err)
		}
		Users = Client.Database("exampleDB").Collection("users")

	case DB_LOCAL_W_AUTH:

		Client, _ = mongo.Connect(nil, options.Client().ApplyURI("mongodb://localhost:27017"))

		// set credentials
		// cred := options.Credential{
		// 	Username: "username",
		// 	Password: "password",
		// }

		// attempt to login
		// err := Client.Auth(cred)
		// if err != nil {
		// 	panic(err)
		// }

		Users = Client.Database("exampleDB").Collection("Users")

	case DB_ATLAS:

		// set Atlas URI
		mongoURI := "mongodb://Sachin125:Btechict%40125@cluster0.spqnong.mongodb.net:27017"

		// dial session with info
		Client, err := mongo.NewClient(options.Client().ApplyURI(mongoURI))
		if err != nil {
			panic(err)
		}
		// tlsConfig := &tls.Config{}
		//tlsConfig := &tls.Config{}
		err = Client.Connect(nil)
		if err != nil {
			panic(err)
		}

		// Define Connections to Databases
		Users = Client.Database("alc_data").Collection("Users")

	}
}
