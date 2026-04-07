package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// ========================
// 1. Модели данных
// ========================

type UserBase struct {
	Username string `json:"username"`
}

type User struct {
	UserBase
	Password string `json:"password"`
}

type UserInDB struct {
	UserBase
	HashedPassword string `json:"hashed_password"`
}

// ========================
// 2. Конфигурация окружения
// ========================

type Config struct {
	Mode         string // DEV или PROD
	DocsUser     string
	DocsPassword string
	Port         string
}

func loadConfig() *Config {
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "DEV" // По умолчанию DEV
	}

	// Валидация MODE
	if mode != "DEV" && mode != "PROD" {
		fmt.Printf("Warning: Invalid MODE='%s', defaulting to DEV\n", mode)
		mode = "DEV"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	return &Config{
		Mode:         mode,
		DocsUser:     os.Getenv("DOCS_USER"),
		DocsPassword: os.Getenv("DOCS_PASSWORD"),
		Port:         port,
	}
}

// ========================
// 3. In-memory база данных
// ========================

var (
	fakeUserDB = make(map[string]UserInDB)
	dbMutex    = &sync.RWMutex{}
)

// ========================
// 4. Хеширование паролей
// ========================

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ========================
// 5. Basic Auth для документации
// ========================

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

// secureCompare - защита от тайминг-атак
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}

// docsAuthMiddleware - middleware для защиты документации
func docsAuthMiddleware(config *Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, что учетные данные настроены
		if config.DocsUser == "" || config.DocsPassword == "" {
			http.Error(w, "Documentation authentication not configured", http.StatusInternalServerError)
			return
		}

		username, password, ok := extractBasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Documentation"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Защита от тайминг-атак
		userMatch := secureCompare(username, config.DocsUser)
		passMatch := secureCompare(password, config.DocsPassword)

		if !userMatch || !passMatch {
			w.Header().Set("WWW-Authenticate", `Basic realm="Documentation"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// ========================
// 6. Основная аутентификация (для /login)
// ========================

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

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ========================
// 7. Обработчики API
// ========================

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
		UserBase:       UserBase{Username: user.Username},
		HashedPassword: hashedPassword,
	}

	dbMutex.Lock()
	fakeUserDB[user.Username] = userInDB
	dbMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User '" + user.Username + "' registered.",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := r.Context().Value("user").(UserInDB)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Welcome, " + user.Username + "!",
	})
}

// ========================
// 8. Кастомная документация (только для DEV)
// ========================

// serveSwaggerUI - возвращает HTML для Swagger UI
func serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {
            SwaggerUIBundle({
                url: "/openapi.json",
                dom_id: '#swagger-ui',
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout"
            });
        }
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// serveOpenAPI - возвращает OpenAPI спецификацию
func serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	spec := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "Educational Credit API",
			"description": "API для управления образовательными кредитами",
			"version":     "1.0.0",
		},
		"servers": []map[string]interface{}{
			{"url": "http://localhost:8000", "description": "Development server"},
		},
		"paths": map[string]interface{}{
			"/register": map[string]interface{}{
				"post": map[string]interface{}{
					"summary":     "Register new user",
					"description": "Создание нового пользователя",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{
									"type": "object",
									"properties": map[string]interface{}{
										"username": map[string]interface{}{"type": "string"},
										"password": map[string]interface{}{"type": "string"},
									},
									"required": []string{"username", "password"},
								},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "User created"},
						"400": map[string]interface{}{"description": "Invalid input"},
					},
				},
			},
			"/login": map[string]interface{}{
				"get": map[string]interface{}{
					"summary":     "Login user",
					"description": "Аутентификация пользователя",
					"security": []map[string]interface{}{
						{"basicAuth": []string{}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Login successful"},
						"401": map[string]interface{}{"description": "Unauthorized"},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"basicAuth": map[string]interface{}{
					"type":   "http",
					"scheme": "basic",
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spec)
}

// ========================
// 9. Настройка роутера в зависимости от режима
// ========================

func setupRouter(config *Config) *mux.Router {
	r := mux.NewRouter()

	// API endpoints (всегда доступны)
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", authUser(loginHandler)).Methods("GET")

	// Настройка документации в зависимости от режима
	if config.Mode == "DEV" {
		fmt.Println("🚀 Running in DEV mode - Documentation enabled with Basic Auth")
		fmt.Printf("📚 Documentation available at: http://localhost:%s/docs\n", config.Port)
		fmt.Printf("🔒 Use credentials: %s / %s\n", config.DocsUser, config.DocsPassword)

		// Защищенные эндпоинты документации
		r.HandleFunc("/docs", docsAuthMiddleware(config, serveSwaggerUI)).Methods("GET")
		r.HandleFunc("/openapi.json", docsAuthMiddleware(config, serveOpenAPI)).Methods("GET")
		// Redoc скрыт (не добавляем маршрут)
	} else {
		// PROD режим - документация полностью отключена (возвращаем 404)
		fmt.Println("🚀 Running in PROD mode - Documentation disabled")

		r.HandleFunc("/docs", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}).Methods("GET")

		r.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}).Methods("GET")

		r.HandleFunc("/redoc", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}).Methods("GET")
	}

	return r
}

// ========================
// 10. Main функция
// ========================

func main() {
	config := loadConfig()

	// Валидация конфигурации для DEV режима
	if config.Mode == "DEV" && (config.DocsUser == "" || config.DocsPassword == "") {
		fmt.Println("⚠️  WARNING: DOCS_USER and DOCS_PASSWORD environment variables are not set!")
		fmt.Println("⚠️  Documentation will be inaccessible!")
	}
	router := setupRouter(config)

	server := &http.Server{
		Addr:         ":" + config.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Printf("✅ Server starting on http://localhost:%s\n", config.Port)
	fmt.Printf("📋 Mode: %s\n", config.Mode)

	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
