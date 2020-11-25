package main

import (
	"net/http"
	"log"
	"os"

	"github.com/julienschmidt/httprouter"
	"github.com/joho/godotenv"

	"go-login/pkg/DBmanager"
	"go-login/internal/handlers"
)

//Main function where router and routes are defined
func main() {
	err := godotenv.Load(".env");
	if err != nil {
		log.Fatal("Error reading .env file");
	}

	db := DBmanager.OpenDB(os.Getenv("DB_USER"), os.Getenv("DB_PASS"), os.Getenv("DB_PROTOCOL"), os.Getenv("DB_ADDR"), os.Getenv("DB_NAME"))
	db.SetMaxOpenConns(151)
	defer db.Close()

	//router here
	router := httprouter.New()
	router.GET("/", handlers.WelcomePage)
	router.POST("/", handlers.UserAuth(db))

	router.POST("/register", handlers.RegisterNewUser(db))

	router.GET("/accounts/:username", handlers.UserHome(db))

	router.GET("/accounts/:username/profile", handlers.Profile(db))
	router.POST("/accounts/:username/profile", handlers.ChangeNick(db))

	log.Fatal(http.ListenAndServe(":8080", router))
}

