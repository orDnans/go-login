package handlers

import (
	"fmt"
	"net/http"
	"encoding/json"
	"database/sql"
	_ "github.com/go-sql-driver/mysql"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"

	"go-login/pkg/JWTmanager"
	"go-login/internal/structs"
)

/* 
Helper functions to decode json
Returns the appropriate struct type
depending on the request body
*/
func decodeLogin(r *http.Request) *structs.LoginInput {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(r.Body)
	var login structs.LoginInput;
	e := decoder.Decode(&login)
	if e != nil {
		fmt.Println(e)
		return nil
	}

	return &login
}

func decodeRegister(r *http.Request) *structs.RegisterInput {
	if r.Body == nil {
		return nil
	}
	decoder := json.NewDecoder(r.Body)
	var register structs.RegisterInput
	e := decoder.Decode(&register)
	if e != nil {
		fmt.Println(e)
		return nil
	}

	return &register
}

func decodeString(r *http.Request) string {
	decoder := json.NewDecoder(r.Body)
	var input structs.OneString
	e := decoder.Decode(&input)
	if e != nil {
		fmt.Println(e)
		return ""
	}
	
	return input.Input
}


/*
Helper function for login and password authentication
Called by userAuth to do so 
*/
func verifyUserPass(l structs.LoginInput, db *sql.DB) bool {
	usernameString := l.User
	queryString := "SELECT pass FROM user_table WHERE usern = \"" + usernameString + "\""

	//we use QueryRow to get only one row because we're assuming that a username is unique 
	//(although usern is not enforced as PK to give accessibility to change it later)
	queryRow := db.QueryRow(queryString)

	//returns a ErrNoRows if query is empty, i.e. username not found
	var passwordString structs.OneString
	e := queryRow.Scan(&passwordString.Input)
	if e != nil {
		fmt.Println("UserAuth - username not found")
		fmt.Println("Error meesage:", e.Error())
		return false
	}

	//confirm password assuming password is stored by hash + salting
	err := bcrypt.CompareHashAndPassword([]byte(passwordString.Input), []byte(l.Pass))
	if err != nil {
		return false
	} else {
		return true
	}
}

/*
Handler Functions for the different routes as assigned to the httprouter in main
These functions can be considered httprouter.Handler 
since they accept httprouter.Params as an argument
*/

//POST request for /, calls for VerifyUserPass
func UserAuth(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		login := decodeLogin(r)
		if login == nil || login.User == "" || login.Pass == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		//login fail
		if !verifyUserPass(*login, db) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		//login successful
		JWTmanager.AssignToken(w, login.User)
		fmt.Fprint(w, "Welcome, ", login.User)
	}
}

//GET request for /
func WelcomePage(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Hello World!")
}

//POST request for /register
func RegisterNewUser(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params){
	return func (w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		registerInfo := decodeRegister(r)
		if registerInfo == nil || registerInfo.Email == "" || registerInfo.Username == "" || registerInfo.Password == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		fmt.Println(registerInfo)

		//check if email exists
		queryString := "SELECT userID FROM user_table WHERE email = \"" + registerInfo.Email + "\""
		fmt.Println(queryString)
		queryResult := db.QueryRow(queryString)
	
		var existingUser structs.OneString
		e := queryResult.Scan(&existingUser.Input)
		if e != sql.ErrNoRows && existingUser.Input != "" {
			fmt.Println("EMAIL ERROR")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	
		//check if username exists
		queryString = "SELECT userID FROM user_table WHERE usern = \"" + registerInfo.Username + "\""
		fmt.Println(queryString)
		queryResult = db.QueryRow(queryString)

		e = queryResult.Scan(&existingUser.Input)
		if e != sql.ErrNoRows && existingUser.Input != "" {
			fmt.Println("USERNAME ERROR")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	
		//generate bcrypt password here
		/*
		passHash, err := bcrypt.GenerateFromPassword([]byte(registerInfo.Password), 8)
		if err != nil {
			fmt.Fprint(w, "Hashing Error")
			return
		}
		*/
	
		//put hash-salted pass into db
		// queryString = "INSERT INTO user_table(usern, email, pass) VALUES (\"" + registerInfo.Username + "\", \"" + registerInfo.Email + "\")"
		// queryString += "\"" + registerInfo.Username + "\", \"" + registerInfo.Email + "\", \"" + string(passHash) + "\")"
		_, insertError := db.Exec("INSERT INTO user_table(usern, email, pass) VALUES (\"" + 
			registerInfo.Username + "\",\"" + registerInfo.Email + "\", \"" + registerInfo.Password + "\");")
		if insertError != nil {
			fmt.Println(insertError)
			fmt.Fprint(w, insertError)
		}
	}
}

//GET request for /accounts/:name
func UserHome(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params){
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		if p.ByName("username") != "" {	
			//check if user exists
			queryString := "SELECT userID FROM user_table WHERE usern = \"" + p.ByName("username") + "\""
			queryRow := db.QueryRow(queryString)
	
			//returns a ErrNoRows if query is empty, i.e. username not found
			var id structs.OneString
			e := queryRow.Scan(&id.Input)
			if e != nil || id.Input == "" {
				fmt.Println("UserHome Error - Expected cause : User not found\nError message: ", e)
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
	
			//greet user
			fmt.Fprintf(w, "Welcome to %v's page\n", p.ByName("username"))
		} else {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
	}
}

//GET request for /accounts/:name/profile
//currently set to require token to access (e.g. like instagram edit profile page)
//since it contains personal information (i.e. email, phone)
func Profile(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		//remove if inefficient
		//theory is O(n + n) = O(n)
		queryString := "SELECT userID FROM user_table WHERE usern = \"" + p.ByName("username") + "\""
		queryRow := db.QueryRow(queryString)

		//returns a ErrNoRows if query is empty, i.e. username not found
		var id structs.OneString
		e := queryRow.Scan(&id.Input)
		if e != nil || id.Input == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		//check if user is logged in (by checking token)
		tokenValid, claims := JWTmanager.CheckToken(w, r)
		if !tokenValid {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		//check if page belongs to 
		if claims.Username != p.ByName("username") {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		queryString = "SELECT usern, email, phone, nickname FROM user_table WHERE usern = \"" + p.ByName("username") + "\""
		queryRow = db.QueryRow(queryString)

		var user_table structs.UserTable
		err := queryRow.Scan(&user_table.Usern, &user_table.Email, &user_table.Phone, &user_table.Nickname)
		if err != nil {
			fmt.Println("Profile Handler Scan Error: ", err)
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}

		fmt.Fprintf(w, "username: %v\nemail: %v\nphone: %v\nnickname: %v\n", 
			user_table.Usern.String, user_table.Email.String, 
			user_table.Phone.String, user_table.Nickname.String)
	}
}

//POST request for /accounts/:name/profile
//changes nickname of user specified in httprouter.Params
func ChangeNick(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		//get the new name from POST body
		newName := decodeString(r)
		if newName == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		//check if user is logged in (by checking token)
		tokenValid, claims := JWTmanager.CheckToken(w, r)
		if !tokenValid {
			fmt.Println("ChangeNick Handler - token invalid")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		//check if page belongs to the one with the claims
		if claims.Username != p.ByName("username") {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	
		//make update query
		queryString := "UPDATE user_table SET nickname = \"" + newName + "\""
		queryString += " WHERE usern = \"" + claims.Username +"\""
		//execute update query
		_, updateErr := db.Exec(queryString)
		if updateErr != nil {
			fmt.Fprint(w, "Internal Error")
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
	
		//write response
		fmt.Fprintf(w, "New nickname: %v\n", newName)
	}
}

