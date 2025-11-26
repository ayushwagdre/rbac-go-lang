#!/bin/bash

set -e

echo "================================================"
echo "  Role-Based Go API - Quick Setup"
echo "================================================"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/desktop/install/mac-install/"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✅ Docker is installed and running"
echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.example..."
    cp .env.example .env

    # Generate a random JWT secret
    JWT_SECRET=$(openssl rand -base64 32 2>/dev/null || LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 43)

    # Replace the JWT_SECRET in .env
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|g" .env
    else
        # Linux
        sed -i "s|JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|g" .env
    fi

    echo "✅ Created .env file with random JWT_SECRET"
else
    echo "ℹ️  .env file already exists, skipping..."
fi

echo ""

# Start PostgreSQL
echo "🐘 Starting PostgreSQL database..."
docker-compose up -d

echo ""
echo "⏳ Waiting for PostgreSQL to be ready..."
sleep 5

# Check if database is ready
until docker exec rolebasedgo-postgres pg_isready -U rolebasedgo &> /dev/null; do
    echo "   Waiting for database..."
    sleep 2
done

echo "✅ PostgreSQL is ready!"
echo ""

# Download Go dependencies
echo "📦 Downloading Go dependencies..."
go mod download
go mod tidy
echo "✅ Dependencies ready!"
echo ""

echo "================================================"
echo "  ✅ Setup Complete!"
echo "================================================"
echo ""
echo "Next steps:"
echo "  1. Run the application:"
echo "     make run"
echo ""
echo "  2. The default admin credentials are:"
echo "     Email: admin@email.com"
echo "     Password: admin123"
echo ""
echo "  3. Test the health endpoint:"
echo "     curl http://localhost:8000/health"
echo ""
echo "Other useful commands:"
echo "  make help       - Show all available commands"
echo "  make db-logs    - View database logs"
echo "  make db-shell   - Connect to PostgreSQL"
echo "  make db-stop    - Stop the database"
echo ""
