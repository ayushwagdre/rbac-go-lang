package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// CONFIGURATION & GLOBALS
// ============================================================================

var (
	db        *sql.DB
	jwtSecret []byte
)

// ============================================================================
// MODELS
// ============================================================================

type User struct {
	ID          int      `json:"id"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	Password    string   `json:"-"`
	Permissions []string `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

type UserCreate struct {
	Name        string   `json:"name" binding:"required"`
	Email       string   `json:"email" binding:"required,email"`
	Password    string   `json:"password" binding:"required,min=6"`
	Permissions []string `json:"permissions"`
}

type UpdateUser struct {
	Name        string   `json:"name" binding:"required"`
	Email       string   `json:"email" binding:"required,email"`
	Permissions []string `json:"permissions"`
}

type UserLogin struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type TokenResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type BlogPost struct {
	ID          int      `json:"id"`
	Title       string   `json:"title" binding:"required"`
	Image       string   `json:"image" binding:"required"`
	Paragraph   string   `json:"paragraph" binding:"required"`
	Content     string   `json:"content" binding:"required"`
	Author      string   `json:"author" binding:"required"`
	Tags        []string `json:"tags" binding:"required"`
	PublishDate string   `json:"publishDate" binding:"required"`
	CreatedAt   time.Time `json:"created_at"`
}

type Portfolio struct {
	ID          int    `json:"id"`
	Title       string `json:"title" binding:"required"`
	Description string `json:"description"`
	Image       string `json:"image" binding:"required"`
	Link        string `json:"link" binding:"required"`
	CreatedAt   time.Time `json:"created_at"`
}

type Testimonial struct {
	ID          int    `json:"id"`
	Star        int    `json:"star" binding:"required,min=1,max=5"`
	Name        string `json:"name" binding:"required"`
	Image       string `json:"image" binding:"required"`
	Content     string `json:"content" binding:"required"`
	Designation string `json:"designation" binding:"required"`
	CreatedAt   time.Time `json:"created_at"`
}

type Claims struct {
	UserID      int      `json:"user_id"`
	Email       string   `json:"email"`
	Permissions []string `json:"permissions"`
	jwt.RegisteredClaims
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

func initDB() error {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		return fmt.Errorf("DATABASE_URL environment variable not set")
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	return createTables()
}

func createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password VARCHAR(255) NOT NULL,
		permissions TEXT[] DEFAULT '{}',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS blogs (
		id SERIAL PRIMARY KEY,
		title VARCHAR(500) NOT NULL,
		image TEXT NOT NULL,
		paragraph TEXT NOT NULL,
		content TEXT NOT NULL,
		author VARCHAR(255) NOT NULL,
		tags TEXT[] DEFAULT '{}',
		publish_date VARCHAR(50) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS portfolios (
		id SERIAL PRIMARY KEY,
		title VARCHAR(500) NOT NULL,
		description TEXT,
		image TEXT NOT NULL,
		link TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS testimonials (
		id SERIAL PRIMARY KEY,
		star INTEGER NOT NULL CHECK (star >= 1 AND star <= 5),
		name VARCHAR(255) NOT NULL,
		image TEXT NOT NULL,
		content TEXT NOT NULL,
		designation VARCHAR(255) NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	`

	_, err := db.Exec(schema)
	return err
}

func initializeAdmin() {
	adminPassword := os.Getenv("ADMIN_PASSWORD")
	if adminPassword == "" {
		adminPassword = "admin123"
		log.Println("⚠️ Warning: ADMIN_PASSWORD not set, using default 'admin123'")
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", "admin@email.com").Scan(&exists)
	if err != nil {
		log.Printf("❌ Error checking admin existence: %v\n", err)
		return
	}

	if exists {
		log.Println("ℹ️ Admin user already exists.")
		return
	}

	hashedPassword, err := hashPassword(adminPassword)
	if err != nil {
		log.Printf("❌ Error hashing admin password: %v\n", err)
		return
	}

	permissions := []string{
		"create_user", "delete_user", "update_user", "view_users",
		"create_blog", "update_blog", "delete_blog", "read_blog",
		"create_portfolio", "update_portfolio", "delete_portfolio", "read_portfolio",
		"create_testimonial", "update_testimonial", "delete_testimonial", "read_testimonial",
	}

	_, err = db.Exec(
		"INSERT INTO users (name, email, password, permissions) VALUES ($1, $2, $3, $4)",
		"Admin", "admin@email.com", hashedPassword, pq.Array(permissions),
	)

	if err != nil {
		log.Printf("❌ Error creating admin user: %v\n", err)
		return
	}

	log.Println("✅ Admin user created!")
}

// ============================================================================
// AUTHENTICATION UTILITIES
// ============================================================================

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateToken(userID int, email string, permissions []string) (string, error) {
	claims := &Claims{
		UserID:      userID,
		Email:       email,
		Permissions: permissions,
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
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
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

// ============================================================================
// MIDDLEWARE
// ============================================================================

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "❌ Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := validateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "❌ Invalid or expired token"})
			c.Abort()
			return
		}

		c.Set("user", claims)
		c.Next()
	}
}

func requirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "❌ Unauthorized"})
			c.Abort()
			return
		}

		claims := user.(*Claims)
		hasPermission := false
		for _, p := range claims.Permissions {
			if p == permission {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("❌ Permission denied: %s required", permission)})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ============================================================================
// USER HANDLERS
// ============================================================================

func createUser(c *gin.Context) {
	var userCreate UserCreate
	if err := c.ShouldBindJSON(&userCreate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", userCreate.Email).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "❌ Email already registered"})
		return
	}

	hashedPassword, err := hashPassword(userCreate.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to hash password"})
		return
	}

	var userID int
	err = db.QueryRow(
		"INSERT INTO users (name, email, password, permissions) VALUES ($1, $2, $3, $4) RETURNING id",
		userCreate.Name, userCreate.Email, hashedPassword, pq.Array(userCreate.Permissions),
	).Scan(&userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to create user"})
		return
	}

	token, _ := generateToken(userID, userCreate.Email, userCreate.Permissions)
	c.JSON(http.StatusCreated, gin.H{
		"id":          userID,
		"permissions": userCreate.Permissions,
		"token":       token,
	})
}

func getAllUsers(c *gin.Context) {
	rows, err := db.Query("SELECT id, name, email, permissions, created_at FROM users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var user User
		var permissions []string
		err := rows.Scan(&user.ID, &user.Name, &user.Email, pq.Array(&permissions), &user.CreatedAt)
		if err != nil {
			continue
		}
		user.Permissions = permissions
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

func getUserByID(c *gin.Context) {
	userID := c.Param("id")
	var user User
	var permissions []string

	err := db.QueryRow(
		"SELECT id, name, email, permissions, created_at FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Name, &user.Email, pq.Array(&permissions), &user.CreatedAt)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ User not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}

	user.Permissions = permissions
	c.JSON(http.StatusOK, user)
}

func updateUser(c *gin.Context) {
	userID := c.Param("id")
	var userCreate UpdateUser
	if err := c.ShouldBindJSON(&userCreate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec(
		"UPDATE users SET name = $1, email = $2, permissions = $4 WHERE id = $5",
		userCreate.Name, userCreate.Email, pq.Array(userCreate.Permissions), userID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to update user"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ User not found"})
		return
	}

	getUserByID(c)
}

func deleteUser(c *gin.Context) {
	userID := c.Param("id")

	var user User
	var permissions []string
	err := db.QueryRow(
		"SELECT id, name, email, permissions FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Name, &user.Email, pq.Array(&permissions))

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ User not found"})
		return
	}

	_, err = db.Exec("DELETE FROM users WHERE id = $1", userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to delete user"})
		return
	}

	user.Permissions = permissions
	c.JSON(http.StatusOK, user)
}

// ============================================================================
// AUTH HANDLERS
// ============================================================================

func login(c *gin.Context) {
	var userLogin UserLogin
	if err := c.ShouldBindJSON(&userLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	var permissions []string
	err := db.QueryRow(
		"SELECT id, email, password, permissions FROM users WHERE email = $1",
		userLogin.Email,
	).Scan(&user.ID, &user.Email, &user.Password, pq.Array(&permissions))

	if err == sql.ErrNoRows || !verifyPassword(userLogin.Password, user.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "❌ Invalid email or password"})
		return
	}

	token, err := generateToken(user.ID, user.Email, permissions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		Token:   token,
		Message: "✅ Login successful",
	})
}

func getMe(c *gin.Context) {
	user, _ := c.Get("user")
	claims := user.(*Claims)

	var userData User
	var permissions []string
	err := db.QueryRow(
		"SELECT id, name, email, permissions FROM users WHERE id = $1",
		claims.UserID,
	).Scan(&userData.ID, &userData.Name, &userData.Email, pq.Array(&permissions))

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ User not found"})
		return
	}

	userData.Permissions = permissions
	c.JSON(http.StatusOK, userData)
}

// ============================================================================
// BLOG HANDLERS
// ============================================================================

func createBlog(c *gin.Context) {
	var blog BlogPost
	if err := c.ShouldBindJSON(&blog); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var blogID int
	err := db.QueryRow(
		`INSERT INTO blogs (title, image, paragraph, content, author, tags, publish_date)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		blog.Title, blog.Image, blog.Paragraph, blog.Content, blog.Author, pq.Array(blog.Tags), blog.PublishDate,
	).Scan(&blogID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to create blog"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": blogID, "message": "✅ Blog created successfully"})
}

func getAllBlogs(c *gin.Context) {
	rows, err := db.Query(`SELECT id, title, image, paragraph, content, author, tags, publish_date, created_at FROM blogs`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}
	defer rows.Close()

	blogs := []BlogPost{}
	for rows.Next() {
		var blog BlogPost
		var tags []string
		err := rows.Scan(&blog.ID, &blog.Title, &blog.Image, &blog.Paragraph, &blog.Content, &blog.Author, pq.Array(&tags), &blog.PublishDate, &blog.CreatedAt)
		if err != nil {
			continue
		}
		blog.Tags = tags
		blogs = append(blogs, blog)
	}

	c.JSON(http.StatusOK, blogs)
}

func getBlogByID(c *gin.Context) {
	blogID := c.Param("id")
	var blog BlogPost
	var tags []string

	err := db.QueryRow(
		`SELECT id, title, image, paragraph, content, author, tags, publish_date, created_at FROM blogs WHERE id = $1`,
		blogID,
	).Scan(&blog.ID, &blog.Title, &blog.Image, &blog.Paragraph, &blog.Content, &blog.Author, pq.Array(&tags), &blog.PublishDate, &blog.CreatedAt)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Blog not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}

	blog.Tags = tags
	c.JSON(http.StatusOK, blog)
}

func updateBlog(c *gin.Context) {
	blogID := c.Param("id")
	var blog BlogPost
	if err := c.ShouldBindJSON(&blog); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec(
		`UPDATE blogs SET title = $1, image = $2, paragraph = $3, content = $4, author = $5, tags = $6, publish_date = $7 WHERE id = $8`,
		blog.Title, blog.Image, blog.Paragraph, blog.Content, blog.Author, pq.Array(blog.Tags), blog.PublishDate, blogID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to update blog"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Blog not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Blog updated successfully"})
}

func deleteBlog(c *gin.Context) {
	blogID := c.Param("id")

	result, err := db.Exec("DELETE FROM blogs WHERE id = $1", blogID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to delete blog"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Blog not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Blog deleted successfully"})
}

// ============================================================================
// PORTFOLIO HANDLERS
// ============================================================================

func createPortfolio(c *gin.Context) {
	var portfolio Portfolio
	if err := c.ShouldBindJSON(&portfolio); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var portfolioID int
	err := db.QueryRow(
		`INSERT INTO portfolios (title, description, image, link) VALUES ($1, $2, $3, $4) RETURNING id`,
		portfolio.Title, portfolio.Description, portfolio.Image, portfolio.Link,
	).Scan(&portfolioID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to create portfolio"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": portfolioID, "message": "✅ Portfolio created successfully"})
}

func getAllPortfolios(c *gin.Context) {
	rows, err := db.Query(`SELECT id, title, description, image, link, created_at FROM portfolios`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}
	defer rows.Close()

	portfolios := []Portfolio{}
	for rows.Next() {
		var portfolio Portfolio
		err := rows.Scan(&portfolio.ID, &portfolio.Title, &portfolio.Description, &portfolio.Image, &portfolio.Link, &portfolio.CreatedAt)
		if err != nil {
			continue
		}
		portfolios = append(portfolios, portfolio)
	}

	c.JSON(http.StatusOK, portfolios)
}

func getPortfolioByID(c *gin.Context) {
	portfolioID := c.Param("id")
	var portfolio Portfolio

	err := db.QueryRow(
		`SELECT id, title, description, image, link, created_at FROM portfolios WHERE id = $1`,
		portfolioID,
	).Scan(&portfolio.ID, &portfolio.Title, &portfolio.Description, &portfolio.Image, &portfolio.Link, &portfolio.CreatedAt)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Portfolio not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}

	c.JSON(http.StatusOK, portfolio)
}

func updatePortfolio(c *gin.Context) {
	portfolioID := c.Param("id")
	var portfolio Portfolio
	if err := c.ShouldBindJSON(&portfolio); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec(
		`UPDATE portfolios SET title = $1, description = $2, image = $3, link = $4 WHERE id = $5`,
		portfolio.Title, portfolio.Description, portfolio.Image, portfolio.Link, portfolioID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to update portfolio"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Portfolio not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Portfolio updated successfully"})
}

func deletePortfolio(c *gin.Context) {
	portfolioID := c.Param("id")

	result, err := db.Exec("DELETE FROM portfolios WHERE id = $1", portfolioID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to delete portfolio"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Portfolio not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Portfolio deleted successfully"})
}

// ============================================================================
// TESTIMONIAL HANDLERS
// ============================================================================

func createTestimonial(c *gin.Context) {
	var testimonial Testimonial
	if err := c.ShouldBindJSON(&testimonial); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var testimonialID int
	err := db.QueryRow(
		`INSERT INTO testimonials (star, name, image, content, designation) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		testimonial.Star, testimonial.Name, testimonial.Image, testimonial.Content, testimonial.Designation,
	).Scan(&testimonialID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to create testimonial"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": testimonialID, "message": "✅ Testimonial created successfully"})
}

func getAllTestimonials(c *gin.Context) {
	rows, err := db.Query(`SELECT id, star, name, image, content, designation, created_at FROM testimonials`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}
	defer rows.Close()

	testimonials := []Testimonial{}
	for rows.Next() {
		var testimonial Testimonial
		err := rows.Scan(&testimonial.ID, &testimonial.Star, &testimonial.Name, &testimonial.Image, &testimonial.Content, &testimonial.Designation, &testimonial.CreatedAt)
		if err != nil {
			continue
		}
		testimonials = append(testimonials, testimonial)
	}

	c.JSON(http.StatusOK, testimonials)
}

func getTestimonialByID(c *gin.Context) {
	testimonialID := c.Param("id")
	var testimonial Testimonial

	err := db.QueryRow(
		`SELECT id, star, name, image, content, designation, created_at FROM testimonials WHERE id = $1`,
		testimonialID,
	).Scan(&testimonial.ID, &testimonial.Star, &testimonial.Name, &testimonial.Image, &testimonial.Content, &testimonial.Designation, &testimonial.CreatedAt)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Testimonial not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Database error"})
		return
	}

	c.JSON(http.StatusOK, testimonial)
}

func updateTestimonial(c *gin.Context) {
	testimonialID := c.Param("id")
	var testimonial Testimonial
	if err := c.ShouldBindJSON(&testimonial); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := db.Exec(
		`UPDATE testimonials SET star = $1, name = $2, image = $3, content = $4, designation = $5 WHERE id = $6`,
		testimonial.Star, testimonial.Name, testimonial.Image, testimonial.Content, testimonial.Designation, testimonialID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to update testimonial"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Testimonial not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Testimonial updated successfully"})
}

func deleteTestimonial(c *gin.Context) {
	testimonialID := c.Param("id")

	result, err := db.Exec("DELETE FROM testimonials WHERE id = $1", testimonialID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "❌ Failed to delete testimonial"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "❌ Testimonial not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "✅ Testimonial deleted successfully"})
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"message": "✅ Server is running",
	})
}

// ============================================================================
// ROUTES SETUP
// ============================================================================

func setupRoutes(r *gin.Engine) {
	// Health check
	r.GET("/health", healthCheck)

	// Auth routes
	auth := r.Group("/auth")
	{
		auth.POST("/login", login)
		auth.GET("/me", authMiddleware(), getMe)
	}

	// User routes
	users := r.Group("/users")
	users.Use(authMiddleware())
	{
		users.GET("/", requirePermission("view_users"), getAllUsers)
		users.POST("/", requirePermission("create_user"), createUser)
		users.GET("/:id", requirePermission("view_users"), getUserByID)
		users.PUT("/:id", requirePermission("update_user"), updateUser)
		users.DELETE("/:id", requirePermission("delete_user"), deleteUser)
	}

	// Blog routes
	blogs := r.Group("/blogs")
	blogs.Use(authMiddleware())
	{
		blogs.GET("/", requirePermission("read_blog"), getAllBlogs)
		blogs.POST("/", requirePermission("create_blog"), createBlog)
		blogs.GET("/:id", requirePermission("read_blog"), getBlogByID)
		blogs.PUT("/:id", requirePermission("update_blog"), updateBlog)
		blogs.DELETE("/:id", requirePermission("delete_blog"), deleteBlog)
	}

	// Portfolio routes
	portfolios := r.Group("/portfolios")
	portfolios.Use(authMiddleware())
	{
		portfolios.GET("/", requirePermission("read_portfolio"), getAllPortfolios)
		portfolios.POST("/", requirePermission("create_portfolio"), createPortfolio)
		portfolios.GET("/:id", requirePermission("read_portfolio"), getPortfolioByID)
		portfolios.PUT("/:id", requirePermission("update_portfolio"), updatePortfolio)
		portfolios.DELETE("/:id", requirePermission("delete_portfolio"), deletePortfolio)
	}

	// Testimonial routes
	testimonials := r.Group("/testimonials")
	testimonials.Use(authMiddleware())
	{
		testimonials.GET("/", requirePermission("read_testimonial"), getAllTestimonials)
		testimonials.POST("/", requirePermission("create_testimonial"), createTestimonial)
		testimonials.GET("/:id", requirePermission("read_testimonial"), getTestimonialByID)
		testimonials.PUT("/:id", requirePermission("update_testimonial"), updateTestimonial)
		testimonials.DELETE("/:id", requirePermission("delete_testimonial"), deleteTestimonial)
	}
}

// ============================================================================
// MAIN FUNCTION
// ============================================================================

func main() {
	// Load JWT secret
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Fatal("❌ JWT_SECRET environment variable not set")
	}

	// Initialize database
	if err := initDB(); err != nil {
		log.Fatal("❌ Failed to initialize database:", err)
	}
	defer db.Close()

	log.Println("✅ Database connected successfully!")

	// Initialize admin user
	initializeAdmin()

	// Setup Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Disable automatic trailing slash redirect to prevent 301 redirects
	r.RedirectTrailingSlash = false

	// CORS configuration
	allowedOrigins := os.Getenv("ALLOWED_ORIGINS")
	if allowedOrigins == "" {
		// Default allowed origins for development and production
		allowedOrigins = "https://admin-dashboard-js-nine.vercel.app,http://localhost:5173,http://localhost:3000"
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(allowedOrigins, ","),
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Setup routes
	setupRoutes(r)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Printf("🚀 Server starting on port %s\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal("❌ Failed to start server:", err)
	}
}
