package DBmanager

import (
	// "fmt"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

func OpenDB (DBusername, DBpass, Protocol, Address, TableName string) *sql.DB {
	//make connection command string
	connectString := DBusername + ":" + DBpass + "@" + Protocol + "(" + Address + ")/" + TableName

	//open a connection to DB
	db, err := sql.Open("mysql", connectString)
	if err != nil {
		panic(err.Error())
	}

	/*
	//check if DB is connected
	err = db.Ping()
	if err != nil {
		fmt.Println("db is not connected")
		panic(err.Error())
	}
	*/

	return db
}