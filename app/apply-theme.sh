#!/bin/bash

# QuantumGuard: Apply Cyberpunk Theme to OWASP Juice Shop
# This script injects the custom cyberpunk theme into the Juice Shop application.

set -e  # Exit on any error

echo "Applying cyberpunk theme to OWASP Juice Shop..."

# Check if the Juice Shop directory exists
JUICE_SHOP_DIR="juice-shop"
if [ ! -d "$JUICE_SHOP_DIR" ]; then
    echo "Error: Juice Shop directory '$JUICE_SHOP_DIR' not found. Please run clone.sh first."
    exit 1
fi

# Check if custom-theme.css exists
THEME_FILE="custom-theme.css"
if [ ! -f "$THEME_FILE" ]; then
    echo "Error: Theme file '$THEME_FILE' not found in the current directory."
    exit 1
fi

# Navigate to Juice Shop directory
cd "$JUICE_SHOP_DIR"

# Check if package.json exists to confirm it's the right project
if [ ! -f "package.json" ]; then
    echo "Error: package.json not found. This might not be the correct Juice Shop repository."
    exit 1
fi

# Find the main CSS file or injection point
# Assuming Juice Shop uses Angular, look for styles in src/assets or similar
STYLES_DIR="src/assets"
if [ ! -d "$STYLES_DIR" ]; then
    echo "Warning: Standard styles directory '$STYLES_DIR' not found. Attempting to find alternative."
    # Try common locations
    STYLES_DIR=$(find . -name "styles" -type d | head -1)
    if [ -z "$STYLES_DIR" ]; then
        echo "Error: Could not find styles directory in Juice Shop."
        exit 1
    fi
fi

# Copy the custom theme to the styles directory
cp "../$THEME_FILE" "$STYLES_DIR/"

echo "Custom theme copied to $STYLES_DIR/$THEME_FILE"

# Inject the theme into the main HTML or CSS file
# For Angular apps, we can modify index.html or main styles
INDEX_FILE="src/index.html"
if [ -f "$INDEX_FILE" ]; then
    # Add link to custom theme in head
    if ! grep -q "$THEME_FILE" "$INDEX_FILE"; then
        sed -i "/<\/head>/i <link rel=\"stylesheet\" href=\"assets/$THEME_FILE\">" "$INDEX_FILE"
        echo "Theme injected into $INDEX_FILE"
    else
        echo "Theme already injected in $INDEX_FILE"
    fi
else
    echo "Warning: $INDEX_FILE not found. Theme copied but not injected automatically."
    echo "You may need to manually add: <link rel=\"stylesheet\" href=\"assets/$THEME_FILE\"> to your HTML."
fi

# Build the application with the theme
echo "Building Juice Shop with cyberpunk theme..."
if command -v npm &> /dev/null; then
    npm install
    npm run build
    echo "Build completed. You can now run the application with Docker."
else
    echo "Warning: npm not found. Please install Node.js and run 'npm install && npm run build' manually."
fi

echo "Cyberpunk theme application completed successfully."
