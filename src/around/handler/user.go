package handler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "regexp"
    "time"

    "around/model"
    "around/service"

    jwt "github.com/form3tech-oss/jwt-go"
)

var mySigningKey = []byte("secret")

func signinHandler(w http.ResponseWriter, r *http.Request) { // pass by ref if you want to update, and it's faster than pass by value
    fmt.Println("Received one signin request")
    w.Header().Set("Content-Type", "text/plain")

    //  Get User information from client
    decoder := json.NewDecoder(r.Body)
    var user model.User
    if err := decoder.Decode(&user); err != nil { // decode json
        http.Error(w, "Cannot decode user data from client", http.StatusBadRequest)
        fmt.Printf("Cannot decode user data from client %v\n", err)
        return
    }

    exists, err := service.CheckUser(user.Username, user.Password)
    if err != nil {
        http.Error(w, "Failed to read user from Elasticsearch", http.StatusInternalServerError)
        fmt.Printf("Failed to read user from Elasticsearch %v\n", err)
        return
    }

    if !exists {
        http.Error(w, "User doesn't exists or wrong password", http.StatusUnauthorized) // 401
        fmt.Printf("User doesn't exists or wrong password\n")
        return
    }

	// successfully login in, create token
	// claim: payload data (original)
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "username": user.Username,
        "exp":      time.Now().Add(time.Hour * 24).Unix(), // expire after 1 day
    })

    tokenString, err := token.SignedString(mySigningKey) // encryptd token
    if err != nil {
        http.Error(w, "Failed to generate token", http.StatusInternalServerError)
        fmt.Printf("Failed to generate token %v\n", err)
        return
    }

    w.Write([]byte(tokenString))
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Println("Received one signup request")
    w.Header().Set("Content-Type", "text/plain")

    decoder := json.NewDecoder(r.Body)
    var user model.User
    if err := decoder.Decode(&user); err != nil {
        http.Error(w, "Cannot decode user data from client", http.StatusBadRequest)
        fmt.Printf("Cannot decode user data from client %v\n", err)
        return
    }

    if user.Username == "" || user.Password == "" || regexp.MustCompile(`^[a-z0-9]$`).MatchString(user.Username) {
														// restrict username input type
        http.Error(w, "Invalid username or password", http.StatusBadRequest)
        fmt.Printf("Invalid username or password\n")
        return
    }

    success, err := service.AddUser(&user)
    if err != nil {
        http.Error(w, "Failed to save user to Elasticsearch", http.StatusInternalServerError)
        fmt.Printf("Failed to save user to Elasticsearch %v\n", err)
        return
    }

    if !success {
        http.Error(w, "User already exists", http.StatusBadRequest)
        fmt.Println("User already exists")
        return
    }
    fmt.Printf("User added successfully: %s.\n", user.Username)
}
