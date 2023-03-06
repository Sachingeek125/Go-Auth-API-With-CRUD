package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Sachingeek125/GolangAuth/routers"
	mux "github.com/gorilla/mux"
)

const port = 8080

func cleanup() {
	log.Printf("Server is being shut downed!......")
}

func main() {

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGALRM)
	go func() {
		<-c
		cleanup()
		os.Exit(0)
	}()

	// define mux router
	r := mux.NewRouter()

	// For registering a newuser
	r.HandleFunc("/register", routers.Register).Methods("POST")
	// for Login with valid credentilas
	r.HandleFunc("/login", routers.Login).Methods("POST")
	// for logout with valid sessionID
	r.HandleFunc("/logout", routers.Logout).Methods("GET")
	// For creating user(but only admin can create a user)
	r.HandleFunc("/users", routers.CreateUser).Methods("POST")
	// for updating a user(user can update only his details but admin can update all users details)
	r.HandleFunc("/users/{id}", routers.UpdateUser).Methods("PUT")
	// for deleting a user(a user can delete his only but admin can delete all of users details)
	r.HandleFunc("/users/{id}", routers.DeleteUser).Methods("DELETE")
	//For getting a user details by userid
	r.HandleFunc("/users/{id}", routers.GetUserByID).Methods("GET")
	// for getting details of all users but currently it only shows it to admin only
	r.HandleFunc("/users", routers.GetAllUsers).Methods("GET")

	// for handling the request
	http.Handle("/", r)

	// starting the new server by port and request
	server := newServer(":"+strconv.Itoa(port), r)
	log.Printf("Starting server on %d", port)
	// closing the server when terminates the program
	defer cleanup()
	// starts and listen the http server respose
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// creating the newserver and assigning attributes to it
func newServer(s string, r *mux.Router) *http.Server {
	return &http.Server{
		Addr:         "127.0.0.1:8080",
		Handler:      r,
		ReadTimeout:  time.Second * 30,
		WriteTimeout: time.Second * 30,
	}

}
