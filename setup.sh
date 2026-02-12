#!/usr/bin/env bash
set -e

# If Docker is not installed, attempt to install it (Ubuntu/Debian).
if ! command -v docker &> /dev/null; then
  echo "Docker not found – installing..."
  sudo apt-get update -y
  sudo apt-get install -y ca-certificates curl gnupg lsb-release
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update -y
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

# Copy .env.example to .env if not present
if [ ! -f .env ]; then
  cp .env.example .env
  echo ".env created – please edit it with real secrets before starting."
else
  echo ".env already exists – using existing values."
fi

# Build and start containers
docker compose up -d --build

echo "\nAll services are up."
echo "Backend API health: http://localhost:3001/health"
echo "Frontend site: http://localhost:3000"
