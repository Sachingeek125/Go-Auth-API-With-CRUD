# Golang Authentication API with Session based authentication using mongodb as database

# Installation

* You should have Go installed on your computer.

* You have a mongodb account and it has an active collection with Go.

# Features
* CRUD (Create, Read, Update, Delete) API endpoints for database management
* User authentication with session based auth
* Admin can use crud opeartion on any user but user can only use crud on his/her own details 
* Based upon current session,current user will be identified.

# Requirments
* Golang(1.16 or Later)
* Mongodb(4.0 or Later)
* Postman(for api testing)

# Installation
* Clone the Repository
```bash
git clone https://github.com/Sachingeek125/Go-Auth-API-With-CRUD.git
```

* Install the required packages
```bash
go get go.mongodb.org/mongo-driver/mongo
go get go.mongodb.org/mongo-driver/bson
go get go.mongodb.org/mongo-driver/mongo/options
go get github.com/gorilla/mux
go get github.com/gorilla/sessions
go get golang.org/x/crypto/bcrypt
```

# Run
* For running this code Just follow below commands:
 ```bash
go build
go run main.go
```


* It will start HTTP server on Localhost port 8080

# Authentication endpoints
## It has 3 endpoints APIs are configured related to the authentication part.

### Register
* Registers a user and stores it info in mongodB and creates a session-id and stores a session into mongodB.
 ```bash
POST /register
```

### Login
* By valid credentials a user can get logged in and a new session also created with unique session-id which have a user-identity user-id also.
 ```bash
POST /login
```

### Logout
* By entering a session-ID into header file a user can logout from his session and it also delets that session from mongodB.
 ```bash
GET /logout
```

# CRUD With AUTH

## so here we have added 4 endpoints for CRUD Operations(Create, read,update,delete).we will be going through each endpoint one by one

## Create
 ```bash
POST /users
```

## Read
* Getting a user by id
 ```bash
GET /users/{id}
```

* Getting all users info(only for admin, for non-admins it will be same as above get)
 ```bash
GET /users
```

## Update
```bash
PUT /users/{id}
```

## Delete
```bash
DELETE /users/{id}
```





