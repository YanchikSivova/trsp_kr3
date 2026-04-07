package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type UserRole string

const (
	RoleAdmin UserRole = "admin"
	RoleUser  UserRole = "user"
	RoleGuest UserRole = "guest"
)

type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Password string   `json:"-"` // Не возвращаем в JSON
	Role     UserRole `json:"role"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"` // admin, user, guest
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Role  string `json:"role"`
}

type Resource struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	UserID string `json:"user_id"`
}

var (
	usersDB        = make(map[string]User)     // key: username
	resourcesDB    = make(map[string]Resource) // key: id
	nextUserID     = 1
	nextResourceID = 1
)

var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

func init() {
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("your-secret-key-change-in-production")
	}
}

type Claims struct {
	Username string   `json:"username"`
	Role     UserRole `json:"role"`
	jwt.RegisteredClaims
}

func generateToken(username string, role UserRole) (string, error) {
	claims := Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		// Проверяем формат "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		claims, err := validateToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Сохраняем claims в контексте
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func requireRole(allowedRoles ...UserRole) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value("claims").(*Claims)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			allowed := false
			for _, role := range allowedRoles {
				if claims.Role == role {
					allowed = true
					break
				}
			}

			if !allowed {
				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Регистрация пользователя
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password required", http.StatusBadRequest)
		return
	}

	var role UserRole
	switch req.Role {
	case "admin":
		role = RoleAdmin
	case "user":
		role = RoleUser
	case "guest":
		role = RoleGuest
	default:
		role = RoleUser
	}

	if _, exists := usersDB[req.Username]; exists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user := User{
		ID:       fmt.Sprintf("%d", nextUserID),
		Username: req.Username,
		Password: hashedPassword,
		Role:     role,
	}
	usersDB[req.Username] = user
	nextUserID++

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "User registered successfully",
		"user": map[string]string{
			"username": user.Username,
			"role":     string(user.Role),
		},
	})
}

// Логин (выдача JWT)
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Находим пользователя
	user, exists := usersDB[req.Username]
	if !exists {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Проверяем пароль
	if !checkPasswordHash(req.Password, user.Password) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Генерируем токен
	token, err := generateToken(user.Username, user.Role)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token: token,
		Role:  string(user.Role),
	})
}

// GET /resources - доступ для всех аутентифицированных пользователей (admin, user, guest)
func getResourcesHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)

	resources := []Resource{}
	for _, res := range resourcesDB {
		// guest видят только свои ресурсы
		if claims.Role == RoleGuest && res.UserID != claims.Username {
			continue
		}
		resources = append(resources, res)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resources)
}

// POST /resources - только admin и user
func createResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)

	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" {
		http.Error(w, "Title required", http.StatusBadRequest)
		return
	}

	resource := Resource{
		ID:     fmt.Sprintf("%d", nextResourceID),
		Title:  req.Title,
		UserID: claims.Username,
	}
	resourcesDB[resource.ID] = resource
	nextResourceID++

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resource)
}

// PUT /resources/{id} - только admin и владелец ресурса (user)
func updateResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	vars := mux.Vars(r)
	id := vars["id"]

	resource, exists := resourcesDB[id]
	if !exists {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	// Проверка прав: admin может обновлять любые, user только свои
	if claims.Role != RoleAdmin && resource.UserID != claims.Username {
		http.Error(w, "Forbidden: you can only update your own resources", http.StatusForbidden)
		return
	}

	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title != "" {
		resource.Title = req.Title
	}
	resourcesDB[id] = resource

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resource)
}

// DELETE /resources/{id} - только admin
func deleteResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)

	// Только admin может удалять
	if claims.Role != RoleAdmin {
		http.Error(w, "Forbidden: only admin can delete resources", http.StatusForbidden)
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if _, exists := resourcesDB[id]; !exists {
		http.Error(w, "Resource not found", http.StatusNotFound)
		return
	}

	delete(resourcesDB, id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Resource deleted successfully"})
}

// GET /admin/users - только admin (просмотр всех пользователей)
func adminGetUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := []map[string]string{}
	for _, user := range usersDB {
		users = append(users, map[string]string{
			"username": user.Username,
			"role":     string(user.Role),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// GET /profile - доступ для всех аутентифицированных (информация о себе)
func profileHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)

	user, exists := usersDB[claims.Username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"username": user.Username,
		"role":     string(user.Role),
	})
}

// GET /protected_resource - только admin и user (guest не может)
func protectedResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "This is a protected resource",
		"user":      claims.Username,
		"role":      claims.Role,
		"timestamp": time.Now().Unix(),
	})
}

func setupRouter() *mux.Router {
	r := mux.NewRouter()

	// Публичные эндпоинты (без аутентификации)
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
			})(w, r)
		})
	})

	api.HandleFunc("/profile", profileHandler).Methods("GET")
	api.HandleFunc("/protected_resource", requireRole(RoleAdmin, RoleUser)(protectedResourceHandler)).Methods("GET")

	api.HandleFunc("/resources", requireRole(RoleAdmin, RoleUser, RoleGuest)(getResourcesHandler)).Methods("GET")
	api.HandleFunc("/resources", requireRole(RoleAdmin, RoleUser)(createResourceHandler)).Methods("POST")
	api.HandleFunc("/resources/{id}", requireRole(RoleAdmin, RoleUser)(updateResourceHandler)).Methods("PUT")
	api.HandleFunc("/resources/{id}", requireRole(RoleAdmin)(deleteResourceHandler)).Methods("DELETE")

	api.HandleFunc("/admin/users", requireRole(RoleAdmin)(adminGetUsersHandler)).Methods("GET")

	return r
}

func main() {
	router := setupRouter()

	// Добавляем middleware для логирования
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("[%s] %s %s\n", time.Now().Format(time.RFC3339), r.Method, r.URL.Path)
			next.ServeHTTP(w, r)
		})
	})

	server := &http.Server{
		Addr:         ":8000",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		panic(err)
	}
}
