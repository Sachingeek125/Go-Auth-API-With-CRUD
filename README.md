# Golang Authentication API with Session based authentication using mongodb as database

# Installation

You should have Go installed on your computer.

You have a mongodb account and it has an active collection with Go.

# Run
For running this code Just follow below commands:
 ```bash
go build
go run main.go
```

It will start HTTP server on Localhost port 8080

It has 3 APIs are configured related to the authentication part.
1. /register
2. /login
3. /logout

# About the testing

you can test this APIs through postman on URL: http://localhost:8080

- /register(POST): it's for newuser, who wants to create an account by giving it's required information including email and password(which are mandatory).this all of registration informations will be stored into the mongodb and it will also create a session which will have a unique sessionID will also store into a mongodb.

- /login(POST): if you're registered user then you have to enter credentilas for login, which includes email and password(into urlencoded form). then our system will check, if these credentilas are valid or not, if it's not valid then it will give an error that email and password both are incorrect.if it's valid then it will create a new session which will be store into mongodb with unique SessionID(which will be used for when you wants to logout from your account).

- /logout(GET): If you wants to logout from your account then you have to enter session-ID into header into header with including a new field named Session-ID.then if your session-ID is valid then it will delete that session from mongodb and will give you the message that session-ID deleted.


# CRUD With AUTH

- so here i've created an admin functionality to change and see details of the all users into a db.where we are retriving a latest session ID from session-db and then decoding a latest user from it and then check if it's admin or user of which details are being requested for update or view or delete.if it's authenticated then move ahead otherwise it will give forbidden message.
