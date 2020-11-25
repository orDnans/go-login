package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"bytes"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/julienschmidt/httprouter"
	 // "golang.org/x/crypto/bcrypt"
	"go-login/pkg/JWTmanager"
	
	"go-login/pkg/DBmanager"
)

/*
Define DB parameters here
regarding port and connection type
*/ 

var DBuser string = "GoAPI"
var DBpass string = "password"
var DBprot string = "tcp"
var DBaddr string = "localhost:3306"
var DBName string = "test_db"

//Testing WelcomePage
func TestWelcomePage(t *testing.T) {
	router := httprouter.New()
	router.GET("/", WelcomePage)

	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}
}

// Testing UserAuth
func TestUserAuth(t *testing.T) {
	//db := DBmanager.OpenDB(DBuser, DBpass, DBprot, DBaddr, DBName)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	// 200 OK
	rows := sqlmock.NewRows([]string{"pass"}).
		AddRow("$2a$08$79S7a/4aJKY97/dwfKHFr.H1zmipI3UplmagNpZS3gAJRHe4rPV/q")
	mock.ExpectQuery("SELECT pass FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(rows)
	// 401 Unauthorized
	rows = sqlmock.NewRows([]string{"pass"}).AddRow("")
	mock.ExpectQuery("SELECT pass FROM user_table WHERE usern = \"usernam\"").WillReturnRows(rows)

	//set up router and recorder
	rr := httptest.NewRecorder()
	router := httprouter.New()
	router.POST("/", UserAuth(db))

	//Testing valid input, expected response 200
	jsonString := bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"sampleUsername\",\"password\":\"samplePassword\"}")
	req, err := http.NewRequest("POST", "/", jsonString)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}

	//Testing nil body, expected response 400
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/", nil)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}

	//Testing empty body, expected response 400
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{}")
	req, err = http.NewRequest("POST", "/", jsonString)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}


	//Testing incorrect body, expected response 401 because expected field doesn't exist
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"User\":\"sampleUsername\",\"Pass\":\"samplePassword\"}")
	req, err = http.NewRequest("POST", "/", jsonString)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}


	//Testing incorrect password, expected response 401
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"usernam\",\"password\":\"passed\"}")
	req, err = http.NewRequest("POST", "/", jsonString)
	if err != nil {
		fmt.Println("UserAuth Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("UserAuth Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusUnauthorized), http.StatusText(rr.Code))
	}
}


func SetCookie(req *http.Request){
	w := httptest.NewRecorder()
	JWTmanager.AssignToken(w, "sampleUsername")
	for i := range w.Result().Cookies() {
		req.AddCookie(w.Result().Cookies()[i])
	}
}

func TestProfile(t *testing.T) {
	// db := DBmanager.OpenDB(DBuser, DBpass, DBprot, DBaddr, DBName)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	//401 unauthorized
	rows := sqlmock.NewRows([]string{"userID"}).AddRow(1)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(rows)

	//200 ok
	rows = sqlmock.NewRows([]string{"userID"}).AddRow(1)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(rows)

	rows = sqlmock.NewRows([]string{"usern", "email", "phone", "nickname"}).
		AddRow("sampleUsername", "sample@someDomain.com", "0123456789", "sample")
	mock.ExpectQuery("SELECT usern, email, phone, nickname FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(rows)

	//403 Forbidden
	rows = sqlmock.NewRows([]string{"userID"}).AddRow(2)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"username\"").WillReturnRows(rows)

	//404 Not Found
	rows = sqlmock.NewRows([]string{"userID"}).AddRow("")
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"abcdefg\"").WillReturnRows(rows)

	//404 Not Found
	rows = sqlmock.NewRows([]string{"userID"}).AddRow("")
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"\"").WillReturnRows(rows)


	//set up router and recorder
	rr := httptest.NewRecorder()
	router := httprouter.New()
	router.GET("/accounts/:username/profile", Profile(db))

	//testing proper input but not logged in, expecting response 401 Unauthorised
	req, err := http.NewRequest("GET", "/accounts/sampleUsername/profile", nil)
	if err != nil {
		fmt.Println("Profile Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Profile Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusUnauthorized), http.StatusText(rr.Code))
	}

	//testing proper input logged in, expecting response 200 OK
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/accounts/sampleUsername/profile", nil)
	if err != nil {
		fmt.Println("Profile Handler Test - Failed making request")
		t.Fatal(err)
	}
	SetCookie(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Profile Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}

	//testing a logged in client accessing the wrong user, expected response 403 Forbidden
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/accounts/username/profile", nil)
	if err != nil {
		fmt.Println("Profile Handler Test - Failed making request")
		t.Fatal(err)
	}
	SetCookie(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("Profile Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusForbidden), http.StatusText(rr.Code))
	}


	//testing non-existent username page, expecting response 404 Not Found
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/accounts/abcdefg/profile", nil)
	if err != nil {
		fmt.Println("Profile Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Profile Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusNotFound), http.StatusText(rr.Code))
	}
	
	//testing empty username, should return 404 Not Found
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/accounts//profile", nil)
	if err != nil {
		fmt.Println("Profile Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("Profile Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusNotFound), http.StatusText(rr.Code))
	}
}

func TestUserHome(t *testing.T) {
	// db := DBmanager.OpenDB(DBuser, DBpass, DBprot, DBaddr, DBName)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	//200 OK
	rows := sqlmock.NewRows([]string{"userID"}).AddRow(1)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(rows)
	//404 Not Found
	rows = sqlmock.NewRows([]string{"userID"}).AddRow("")
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"abcdefg\"").WillReturnRows(rows)
	//404 Not Found
	rows = sqlmock.NewRows([]string{"userID"}).AddRow("")
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"\"").WillReturnRows(rows)

	//set up router and recorder
	rr := httptest.NewRecorder()
	router := httprouter.New()
	router.GET("/accounts/:username", UserHome(db))

	//testing valid username, return 200 OK
	req, err := http.NewRequest("GET", "/accounts/sampleUsername", nil)
	if err != nil {
		fmt.Println("UserHome Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("UserHome Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}

	//testing invalid
	rr = httptest.NewRecorder() 
	req, err = http.NewRequest("GET", "/accounts/abcdefg", nil)
	if err != nil {
		fmt.Println("UserHome Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("UserHome Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusNotFound), http.StatusText(rr.Code))
	}

	//testing empty
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/accounts/", nil)
	if err != nil {
		fmt.Println("UserHome Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("UserHome Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusNotFound), http.StatusText(rr.Code))
	}
}

func TestChangeNick(t *testing.T) {
	// db := DBmanager.OpenDB(DBuser, DBpass, DBprot, DBaddr, DBName)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	mock.ExpectExec("UPDATE user_table SET nickname = \"newNickname\" WHERE usern = \"sampleUsername\"").
		WillReturnResult(sqlmock.NewResult(0, 1))

	//set up router and recorder
	rr := httptest.NewRecorder()
	router := httprouter.New()
	router.POST("/accounts/:username/profile", ChangeNick(db))

	//testing correct body, no authorization - expected 401 unauthorised
	jsonString := bytes.NewBufferString("")
	jsonString.WriteString("{\"nickname\":\"newNickname\"}")
	req, err := http.NewRequest("POST", "/accounts/sampleUsername/profile", jsonString)
	if err != nil {
		fmt.Println("ChangeNick Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("ChangeNick Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusUnauthorized), http.StatusText(rr.Code))
	}

	//testing correct body but invalid authorization - expect 403 forbidden
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"nickname\":\"newNickname\"}")
	req, err = http.NewRequest("POST", "/accounts/imsorry/profile", jsonString)
	if err != nil {
		fmt.Println("ChangeNick Handler Test - Failed making request")
		t.Fatal(err)
	}
	SetCookie(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("ChangeNick Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusForbidden), http.StatusText(rr.Code))
	}

	//testing correct body and valid authorization - expecting 200 OK
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"nickname\":\"newNickname\"}")
	req, err = http.NewRequest("POST", "/accounts/sampleUsername/profile", jsonString)
	if err != nil {
		fmt.Println("ChangeNick Handler Test - Failed making request")
		t.Fatal(err)
	}
	SetCookie(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("ChangeNick Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}

	//testing valid authorization but incorrect body - expecting 400 bad request
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"nick\":\"newNickname\"}")
	req, err = http.NewRequest("POST", "/accounts/sampleUsername/profile", jsonString)
	if err != nil {
		fmt.Println("ChangeNick Handler Test - Failed making request")
		t.Fatal(err)
	}
	SetCookie(req)
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("ChangeNick Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}
}

func TestRegisterNewUser(t *testing.T) {

	db := DBmanager.OpenDB(DBuser, DBpass, DBprot, DBaddr, DBName)
	defer db.Close()


	newUsername := "user1"
	newEmail := "user1@domain.com"
	newPassword := "pass1"

	/*
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()


	row1 := sqlmock.NewRows([]string{"userID"}).AddRow(nil)
	row2 := sqlmock.NewRows([]string{"userID"}).AddRow(1)

	//200 OK
	mock.ExpectQuery("SELECT userID FROM user_table WHERE email = \"email@domain.com\"").WillReturnRows(row1)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"user1\"").WillReturnRows(row1)
	mock.ExpectExec("INSERT INTO user_table(usern, email) VALUES (\"user1\", \"email@domain.com\");").
		WillReturnResult(sqlmock.NewResult(1,1))

	//401 email used
	mock.ExpectQuery("SELECT userID FROM user_table WHERE email = \"unauthorized@domain.com\"").WillReturnRows(row2)

	//401 usern taken
	mock.ExpectQuery("SELECT userID FROM user_table WHERE email = \"untakenEmail@domain.com\"").WillReturnRows(row1)
	mock.ExpectQuery("SELECT userID FROM user_table WHERE usern = \"sampleUsername\"").WillReturnRows(row2)
	*/

	rr := httptest.NewRecorder()
	router := httprouter.New()
	router.POST("/register", RegisterNewUser(db))

	//test unregistered account, expected status 200
	jsonString := bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"" + newUsername + "\",\"email\":\"" + newEmail + "\",\"password\":\"" + newPassword + "\"}")

	req, err := http.NewRequest("POST", "/register", jsonString)
	if err != nil {
		fmt.Println("RegisterNewUser Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("RegisterNewUser Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusOK), http.StatusText(rr.Code))
	}

	//test registered account, expected status 401 unauthorized with message email taken
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"" + newUsername + "\",\"email\":\"" + newEmail + "\",\"password\":\"" + newPassword + "\"}")

	req, err = http.NewRequest("POST", "/register", jsonString)
	if err != nil {
		fmt.Println("RegisterNewUser Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("RegisterNewUser Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusUnauthorized), http.StatusText(rr.Code))
	}
	
	//test registered username, expected status 401 unauthorized with message usern taken
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"sampleUsername\",\"email\":\"untakenEmail@domain.com\",\"password\":\"" + newPassword + "\"}")

	req, err = http.NewRequest("POST", "/register", jsonString)
	if err != nil {
		fmt.Println("RegisterNewUser Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("RegisterNewUser Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusUnauthorized), http.StatusText(rr.Code))
	}

	//test missing fields, expected status 400 bad request
	rr = httptest.NewRecorder()
	jsonString = bytes.NewBufferString("")
	jsonString.WriteString("{\"username\":\"\",\"email\":\"\",\"password\":\"" + newPassword + "\"}")

	req, err = http.NewRequest("POST", "/register", jsonString)
	if err != nil {
		fmt.Println("RegisterNewUser Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("RegisterNewUser Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}

	//test empty body, expected status 400 bad request
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/register", nil)
	if err != nil {
		fmt.Println("RegisterNewUser Handler Test - Failed making request")
		t.Fatal(err)
	}
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("RegisterNewUser Handler Incorrect Response\nExpected:%v, Got:%v", http.StatusText(http.StatusBadRequest), http.StatusText(rr.Code))
	}
}