package main

import (
	"database/sql"
	"fmt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"os"
)

var db *sql.DB

func initDB() error {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found")
	}
	host := os.Getenv("DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("DB_PORT")
	if port == "" {
		port = "5432"
	}
	user := os.Getenv("DB_USER")
	if user == "" {
		user = "postgres"
	}
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		dbname = "usersdb"
	}
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", host, port, user, password, dbname)
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("error opening database: %w", err)
	}
	log.Printf("Connected to database")
	return nil
}

func createTable() error {
	query := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("error creating users: %w", err)
	}
	log.Printf("Created users")
	return nil
}

func insertUser(username, password string) error {
	query := `INSERT INTO users (username, password) VALUES ($1, $2);`
	_, err := db.Exec(query, username, password)
	if err != nil {
		return fmt.Errorf("error inserting user: %w", err)
	}
	return nil
}

func userExists(username string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)`
	var exists bool
	err := db.QueryRow(query, username).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("error checking user: %w", err)
	}
	return exists, nil
}

func closeDB() {
	if db != nil {
		db.Close()
		log.Printf("Closed database connection")
	}
}
