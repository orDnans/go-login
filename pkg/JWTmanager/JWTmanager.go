package JWTmanager

import (
	"fmt"
	"net/http"
	"strings"
	"crypto/rand"
	
	"github.com/dgrijalva/jwt-go"
	"time"
)

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

//var keyString = []byte("beentrytask")

func GenerateSecretKey(n int) []byte {
	key := make([]byte, n)
	_, genErr := rand.Read(key)
	if genErr != nil {
		fmt.Println("Generating crypto-secure random num failed")
		panic(fmt.Sprintf("Generating crypto-secure random num failed, Error: %v", genErr))
	}

	return key
}

var keyString = GenerateSecretKey(32)

func AssignToken(w http.ResponseWriter, usern string) {
	//set JWT time expiry
	expirationTime := time.Now().Add(60 * time.Minute)

	//set JWT claims
	claims := &Claims {
		Username: usern,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//make JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	//generate signed string
	//header + payload(claims) + secretKey(keyString)  ----HMAC algo + SHA256---> signature
	//Base64(header) + "." + Base64(payload) + "." + Base64(signature) = signed string (kept in tokenString)
	tokenString, err := token.SignedString(keyString)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	//make cookie for client
	http.SetCookie(w, &http.Cookie{
		Name: "Authorization",
		Value: "Bearer " + tokenString,
		Expires: expirationTime,
	})
}

func CheckToken(w http.ResponseWriter, r *http.Request) (bool, *Claims) {
	//Check Cookie
	c, err := r.Cookie("Authorization")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return false, nil
		}
		w.WriteHeader(http.StatusBadRequest)
		return false, nil
	}

	//get token string, removing the "Bearer" front
	tokenString := strings.Fields(c.Value)[1]

	//initialise a new instance of claims
	claims := &Claims{}

	//verify token while also parsing jwt string payload and store result in claims
	//note that we are passing the secret keyword in this method through the function literal
	//This method will return an error if the token is invalid/past expiry/signature does not match
	token, err := jwt.ParseWithClaims(tokenString, claims, func(tkn *jwt.Token) (interface{}, error) {
			return keyString, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid{
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return false, nil
		}
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return false, nil
	}

	if !token.Valid {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return false, nil
	}

	return true, claims;
}