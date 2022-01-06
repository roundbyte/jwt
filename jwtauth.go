package main

import (
	"encoding/json"
	"strings"
	"log"
	"os"
	"time"
	"net/http"
	"github.com/gorilla/mux"
	jwt "github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("my_secret_key")

type Credentials struct {
	Username string `json:"username"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type Token struct {
	AccessToken string `json:"access_token"`
	TokenType string `json:"token_type"`
}

func renderJSON(w http.ResponseWriter, v interface{}) {
	js, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func genToken(w http.ResponseWriter, req *http.Request) {
	log.Printf("handling task gentoken at %s", req.URL.Path)
	var creds Credentials
	err := json.NewDecoder(req.Body).Decode(&creds)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expirationTime := time.Now().Add(45 * time.Second)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jstoken := &Token{
		AccessToken: tokenString,
		TokenType: "bearer",
	}
	//w.Header().Set("Authorization", fmt.Sprintf("Bearer %s", tokenString))
	renderJSON(w, jstoken)
}

func checkToken(w http.ResponseWriter, req *http.Request) {
	log.Printf("handling task checkToken at %s", req.URL.Path)
	jwtString := req.Header.Get("Authorization");
	jwtString = strings.Split(jwtString, "Bearer ")[1]
	log.Printf("Authorization header: %s", jwtString)
	token, err := jwt.ParseWithClaims(
		jwtString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		},
	)
	if err != nil {
		log.Printf("Error parsing Claims %s", err)
		return
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		log.Printf("Fail")
		return
	}
	log.Printf("%v", claims)
	w.Write([]byte("thx"))
}

func main() {
	router := mux.NewRouter()
	router.StrictSlash(true)

	router.HandleFunc("/gentoken/", genToken).Methods("POST")
	router.HandleFunc("/checktoken/", checkToken).Methods("GET")
	//router.HandleFunc("/refresh/", Refresh).Methods("GET")

	log.Printf("Listening and serving on port %s", os.Getenv("SERVERPORT"))
	log.Fatal(http.ListenAndServe("localhost:"+os.Getenv("SERVERPORT"), router))
}
