# Role-Based Access Control (RBAC) API - Golang + PostgreSQL

A single-file Golang REST API implementing role-based access control with JWT authentication, using PostgreSQL as the database.

## Features

- **Authentication & Authorization**: JWT-based authentication with permission-based access control
- **User Management**: Full CRUD operations for users with role permissions
- **Blog Management**: Create, read, update, and delete blog posts
- **Portfolio Management**: Manage portfolio items
- **Testimonial Management**: Handle testimonials
- **Auto Admin Initialization**: Automatically creates an admin user on first run
- **Single File**: Entire application in one Go file for easy deployment

## Tech Stack

- **Language**: Go 1.21+
- **Web Framework**: Gin
- **Database**: PostgreSQL
- **Authentication**: JWT (golang-jwt/jwt)
- **Password Hashing**: bcrypt
- **CORS**: gin-contrib/cors

## Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose (recommended) OR PostgreSQL 12 or higher

## Quick Start (Recommended)

The fastest way to get started using Docker:

```bash
# Run the automated setup script
./setup.sh

# Start the application
make run
```

That's it! The setup script will:
- Create a `.env` file with secure defaults
- Start PostgreSQL in Docker
- Download Go dependencies
- Initialize the database

### Quick Commands

```bash
make help         # Show all available commands
make setup        # Initial setup (create .env and start database)
make run          # Run the application
make db-start     # Start PostgreSQL
make db-stop      # Stop PostgreSQL
make db-logs      # View database logs
make db-shell     # Connect to PostgreSQL shell
make build        # Build the binary
make clean        # Clean up everything
```

## Manual Installation

1. Navigate to the project directory:
```bash
cd role-based-go
```

2. Copy the environment file:
```bash
cp .env.example .env
```

3. Configure your `.env` file with your PostgreSQL credentials:
```env
DATABASE_URL=postgres://username:password@localhost:5432/dbname?sslmode=disable
JWT_SECRET=your-super-secret-jwt-key
ADMIN_PASSWORD=your-admin-password
PORT=8000
ALLOWED_ORIGINS=http://localhost:3000
```

4. Initialize Go modules and download dependencies:
```bash
go mod download
```

## Database Setup

### Option 1: Docker (Recommended)

The project includes a `docker-compose.yml` file:

```bash
# Start PostgreSQL
make db-start

# Or manually:
docker-compose up -d
```

This will start PostgreSQL with the credentials from `.env.example`.

### Option 2: Local PostgreSQL

1. Create an empty PostgreSQL database:
```sql
CREATE DATABASE your_database_name;
```

2. Update the `DATABASE_URL` in your `.env` file

The application automatically creates all required tables on startup:
- `users` - User accounts with permissions
- `blogs` - Blog posts
- `portfolios` - Portfolio items
- `testimonials` - Testimonials

## Running the Application

### Using Make (Recommended)

```bash
make run
```

### Direct with Go

```bash
# Load environment variables and run
export $(cat .env | xargs) && go run main.go
```

### Using the built binary

```bash
make build
export $(cat .env | xargs) && ./bin/server
```

The server will start on the port specified in your `.env` file (default: 8000).

## Default Admin Credentials

On first run, an admin user is automatically created:

- **Email**: `admin@email.com`
- **Password**: Value from `ADMIN_PASSWORD` in `.env` (default: `admin123`)

The admin has all permissions:
- User management: `create_user`, `update_user`, `delete_user`, `view_users`
- Blog management: `create_blog`, `update_blog`, `delete_blog`, `read_blog`
- Portfolio management: `create_portfolio`, `update_portfolio`, `delete_portfolio`, `read_portfolio`
- Testimonial management: `create_testimonial`, `update_testimonial`, `delete_testimonial`, `read_testimonial`

## API Endpoints

### Authentication

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "admin@email.com",
  "password": "admin123"
}

Response:
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "message": "✅ Login successful"
}
```

#### Get Current User
```http
GET /auth/me
Authorization: Bearer <token>

Response:
{
  "id": 1,
  "name": "Admin",
  "email": "admin@email.com",
  "permissions": ["create_user", "delete_user", ...]
}
```

### Users

#### Create User
```http
POST /users
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "password123",
  "permissions": ["read_blog", "read_portfolio"]
}
```

#### Get All Users
```http
GET /users
Authorization: Bearer <token>
```

#### Get User by ID
```http
GET /users/:id
Authorization: Bearer <token>
```

#### Update User
```http
PUT /users/:id
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "John Updated",
  "email": "john@example.com",
  "password": "newpassword123",
  "permissions": ["read_blog"]
}
```

#### Delete User
```http
DELETE /users/:id
Authorization: Bearer <token>
```

### Blogs

#### Create Blog
```http
POST /blogs
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My First Blog",
  "image": "https://example.com/image.jpg",
  "paragraph": "Short description",
  "content": "Full blog content here...",
  "author": "John Doe",
  "tags": ["golang", "api", "tutorial"],
  "publishDate": "2025-01-15"
}
```

#### Get All Blogs
```http
GET /blogs
Authorization: Bearer <token>
```

#### Get Blog by ID
```http
GET /blogs/:id
Authorization: Bearer <token>
```

#### Update Blog
```http
PUT /blogs/:id
Authorization: Bearer <token>
Content-Type: application/json
```

#### Delete Blog
```http
DELETE /blogs/:id
Authorization: Bearer <token>
```

### Portfolios

#### Create Portfolio
```http
POST /portfolios
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "My Project",
  "description": "Project description",
  "image": "https://example.com/project.jpg",
  "link": "https://github.com/username/project"
}
```

#### Get All Portfolios
```http
GET /portfolios
Authorization: Bearer <token>
```

#### Get Portfolio by ID
```http
GET /portfolios/:id
Authorization: Bearer <token>
```

#### Update Portfolio
```http
PUT /portfolios/:id
Authorization: Bearer <token>
Content-Type: application/json
```

#### Delete Portfolio
```http
DELETE /portfolios/:id
Authorization: Bearer <token>
```

### Testimonials

#### Create Testimonial
```http
POST /testimonials
Authorization: Bearer <token>
Content-Type: application/json

{
  "star": 5,
  "name": "Jane Smith",
  "image": "https://example.com/jane.jpg",
  "content": "Great service!",
  "designation": "CEO, Company Inc"
}
```

#### Get All Testimonials
```http
GET /testimonials
Authorization: Bearer <token>
```

#### Get Testimonial by ID
```http
GET /testimonials/:id
Authorization: Bearer <token>
```

#### Update Testimonial
```http
PUT /testimonials/:id
Authorization: Bearer <token>
Content-Type: application/json
```

#### Delete Testimonial
```http
DELETE /testimonials/:id
Authorization: Bearer <token>
```

### Health Check

```http
GET /health

Response:
{
  "status": "healthy",
  "message": "✅ Server is running"
}
```

## Permission System

The application uses a permission-based access control system. Each user has a list of permissions that determine what actions they can perform.

### Available Permissions

**User Management:**
- `create_user` - Create new users
- `view_users` - View user list and details
- `update_user` - Update user information
- `delete_user` - Delete users

**Blog Management:**
- `create_blog` - Create blog posts
- `read_blog` - Read blog posts
- `update_blog` - Update blog posts
- `delete_blog` - Delete blog posts

**Portfolio Management:**
- `create_portfolio` - Create portfolio items
- `read_portfolio` - Read portfolio items
- `update_portfolio` - Update portfolio items
- `delete_portfolio` - Delete portfolio items

**Testimonial Management:**
- `create_testimonial` - Create testimonials
- `read_testimonial` - Read testimonials
- `update_testimonial` - Update testimonials
- `delete_testimonial` - Delete testimonials

## Building for Production

### Build the binary:
```bash
go build -o server main.go
```

### Run the binary:
```bash
./server
```

### Build for different platforms:

**Linux:**
```bash
GOOS=linux GOARCH=amd64 go build -o server-linux main.go
```

**Windows:**
```bash
GOOS=windows GOARCH=amd64 go build -o server.exe main.go
```

**macOS:**
```bash
GOOS=darwin GOARCH=amd64 go build -o server-mac main.go
```

## Docker Deployment

### Development with Docker Compose

The project includes a `docker-compose.yml` for PostgreSQL:

```bash
# Start database
make db-start

# View logs
make db-logs

# Connect to PostgreSQL shell
make db-shell

# Stop database
make db-stop

# Clean up (removes volumes)
make clean
```

### Production Docker Build

Create a `Dockerfile`:

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN go build -o server main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/server .
EXPOSE 8000
CMD ["./server"]
```

Build and run:
```bash
docker build -t role-based-api .
docker run -p 8000:8000 --env-file .env role-based-api
```

## Security Considerations

1. **Change default credentials**: Always change the admin password in production
2. **Use strong JWT secret**: Generate a strong random string for `JWT_SECRET`
3. **Enable SSL/TLS**: Use HTTPS in production
4. **Database security**: Use strong database passwords and restrict access
5. **CORS**: Configure `ALLOWED_ORIGINS` appropriately for your frontend
6. **Environment variables**: Never commit `.env` file to version control

## Error Handling

The API returns appropriate HTTP status codes:

- `200 OK` - Successful GET, PUT
- `201 Created` - Successful POST
- `400 Bad Request` - Invalid request data
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

All error responses include a descriptive error message.

## Development

### Running tests:
```bash
go test -v
```

### Format code:
```bash
go fmt main.go
```

### Lint code:
```bash
golangci-lint run
```

## Project Structure

This is a single-file application (`main.go`) organized into sections:

1. **Configuration & Globals** - Environment setup and global variables
2. **Models** - Data structures and types
3. **Database Initialization** - Connection and schema creation
4. **Authentication Utilities** - JWT and password handling
5. **Middleware** - Authentication and authorization
6. **Handlers** - HTTP request handlers for each resource
7. **Routes Setup** - Route definitions
8. **Main Function** - Application entry point

## Troubleshooting

### Database connection errors:
- Verify PostgreSQL is running
- Check `DATABASE_URL` format and credentials
- Ensure database exists

### JWT errors:
- Verify `JWT_SECRET` is set
- Check token expiration (default: 24 hours)

### Permission denied errors:
- Verify user has required permissions
- Check JWT token is valid

## Testing with cURL

### Login:
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@email.com","password":"admin123"}'
```

### Get current user:
```bash
curl -X GET http://localhost:8000/auth/me \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create a blog post:
```bash
curl -X POST http://localhost:8000/blogs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "My Blog",
    "image": "https://example.com/img.jpg",
    "paragraph": "Short desc",
    "content": "Full content",
    "author": "Admin",
    "tags": ["golang", "api"],
    "publishDate": "2025-01-15"
  }'
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
