package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Userbase struct {
	Username string `json:"username"`
}

type User struct {
	Userbase
	Password string `json:"password"`
}

type UserInDB struct {
	Userbase
	HashedPassword string `json:"hashed_password"`
}

var (
	fakeUserDB = make(map[string]UserInDB)
	dbMutex    = &sync.RWMutex{}
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func extractBasicAuth(r *http.Request) (username, password string, ok bool) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", false
	}

	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", "", false
	}
	payload, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(payload), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func secureCompare(a string, b string) bool {
	return subtleConstantTimeCompare(a, b)
}

func subtleConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

func authUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := extractBasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		dbMutex.RLock()
		user, exists := fakeUserDB[username]
		dbMutex.RUnlock()

		dummyHash := "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyha"
		if !exists {
			_ = checkPasswordHash(password, dummyHash)
			_ = secureCompare(username, "dummy_username_for_timing_attack")
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !checkPasswordHash(password, user.HashedPassword) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !secureCompare(username, user.Username) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := r.Context()
		ctx = contextSetUser(ctx, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

type contextKey string

const userContextKey contextKey = "user"

func contextSetUser(ctx context.Context, user UserInDB) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
func contextGetUser(ctx context.Context) (UserInDB, bool) {
	user, ok := ctx.Value(userContextKey).(UserInDB)
	return user, ok
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request Body", http.StatusBadRequest)
		return
	}
	if user.Username == "" || user.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}
	dbMutex.RLock()
	_, exists := fakeUserDB[user.Username]
	dbMutex.RUnlock()
	if exists {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}
	hashedPassword, err := hashPassword(user.Password)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	userInDB := UserInDB{
		Userbase:       Userbase{Username: user.Username},
		HashedPassword: hashedPassword,
	}
	dbMutex.Lock()
	fakeUserDB[user.Username] = userInDB
	dbMutex.Unlock()
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User '" + user.Username + "' registered.",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := contextGetUser(r.Context())
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User '" + user.Username + "' logged in.",
	})
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", authUser(loginHandler)).Methods("GET")
	server := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Server starting on http://localhost:8000")
	}
}
