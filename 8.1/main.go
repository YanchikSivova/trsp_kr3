package main

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	if req.Password == "" {
		http.Error(w, "Password is required", http.StatusBadRequest)
		return
	}
	exists, err := userExists(req.Username)
	if err != nil {
		log.Printf("Error checking if user exists: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}
	err = insertUser(req.Username, req.Password)
	if err != nil {
		log.Printf("Error inserting user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(RegisterResponse{
		Message: "User registered successfully!",
	})
}

func main() {
	if err := initDB(); err != nil {
		log.Fatalf("failed to initialize database: %w", err)
	}
	defer closeDB()
	if err := createTable(); err != nil {
		log.Fatalf("failed to create Table: %w", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/register", registerHandler).Methods("POST")
	port := ":8000"
	log.Printf("Server starting on http://localhost%s", port)

	if err := http.ListenAndServe(port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
