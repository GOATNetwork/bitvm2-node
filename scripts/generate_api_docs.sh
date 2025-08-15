#!/bin/bash

# BitVM2 Node API Documentation Generation Script
# Generate complete API documentation using rust-doc

set -e

echo "🚀 Starting BitVM2 Node API documentation generation..."

# Check if we're in the correct directory
if [ ! -f "Cargo.toml" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

# Create documentation directory
DOCS_DIR="docs/api"
mkdir -p "$DOCS_DIR"

echo "📁 Creating documentation directory: $DOCS_DIR"

# Generate rust-doc documentation
echo "📚 Generating rust-doc documentation..."
cargo doc --no-deps --target-dir "$DOCS_DIR"

if [ $? -eq 0 ]; then
    echo "✅ rust-doc documentation generated successfully!"
    
    # Copy generated documentation to target directory
    if [ -d "$DOCS_DIR/doc" ]; then
        echo "📋 Copying documentation files..."
        cp -r "$DOCS_DIR/doc"/* "$DOCS_DIR/"
        rm -rf "$DOCS_DIR/doc"
    fi
    
    echo ""
    echo "🎉 API documentation generation completed!"
    echo ""
    echo "📖 Documentation locations:"
    echo "   - HTML documentation: $DOCS_DIR/index.html"
    echo "   - Main documentation: $DOCS_DIR/bitvm2_noded/index.html"
    echo "   - RPC service docs: $DOCS_DIR/bitvm2_noded/rpc_service/index.html"
    echo ""
    echo "🔗 View documentation:"
    echo "   - Open in browser: $DOCS_DIR/index.html"
    echo "   - Or run: open $DOCS_DIR/index.html"
    echo ""
    echo "📝 Documentation includes:"
    echo "   - Complete API endpoint descriptions"
    echo "   - Request and response examples"
    echo "   - Parameter descriptions"
    echo "   - Error code descriptions"
    echo "   - Complete rust-doc comments"
    
    # Check if documentation files exist
    if [ -f "$DOCS_DIR/index.html" ]; then
        echo ""
        echo "✅ Documentation files found successfully!"
        
        # Optional: automatically open browser
        if command -v open >/dev/null 2>&1; then
            echo ""
            read -p "Would you like to automatically open the documentation in your browser? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                open "$DOCS_DIR/index.html"
            fi
        fi
    else
        echo ""
        echo "⚠️  Warning: Documentation files not found in expected location"
        echo "   Checking for alternative locations..."
        
        # Look for documentation in other possible locations
        if [ -d "$DOCS_DIR/bitvm2_noded" ]; then
            echo "   Found documentation in: $DOCS_DIR/bitvm2_noded/"
            if [ -f "$DOCS_DIR/bitvm2_noded/index.html" ]; then
                echo "   Main documentation: $DOCS_DIR/bitvm2_noded/index.html"
            fi
        fi
    fi
    
else
    echo "❌ Documentation generation failed!"
    exit 1
fi
