#!/bin/bash

# QuantumGuard: Clone OWASP Juice Shop with Error Handling
# This script downloads the OWASP Juice Shop repository for use as a vulnerable training application.

set -e  # Exit on any error

echo "Starting OWASP Juice Shop clone process..."

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "Error: Git is not installed. Please install Git and try again."
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed. Please install Docker and try again."
    exit 1
fi

# Define repository URL and target directory
REPO_URL="https://github.com/juice-shop/juice-shop.git"
TARGET_DIR="juice-shop"

# Check if target directory already exists
if [ -d "$TARGET_DIR" ]; then
    echo "Warning: Directory '$TARGET_DIR' already exists. Removing it to clone fresh."
    rm -rf "$TARGET_DIR"
fi

# Clone the repository
echo "Cloning OWASP Juice Shop from $REPO_URL..."
if git clone "$REPO_URL" "$TARGET_DIR"; then
    echo "Successfully cloned OWASP Juice Shop."
else
    echo "Error: Failed to clone the repository. Please check your internet connection and try again."
    exit 1
fi

# Navigate to the cloned directory
cd "$TARGET_DIR"

# Check if package.json exists (to confirm it's the right repo)
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. This might not be the correct repository."
    exit 1
fi

echo "Clone process completed successfully. You can now build and run the application with Docker."
echo "Run: docker build -t juice-shop . && docker run -d -p 3000:3000 juice-shop"
