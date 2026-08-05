#!/bin/bash

# BitVM Node API Documentation Server
# Use Python built-in server to provide documentation access

set -e

DOCS_DIR="docs/api"
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"

# Show usage
show_usage() {
    echo "Usage:"
    echo "  ./scripts/serve_docs.sh [options]"
    echo ""
    echo "Options:"
    echo "  -h, --host HOST          Bind host address [default: 0.0.0.0]"
    echo "  -p, --port PORT          Server port [default: 8080]"
    echo "  --help                   Show help information"
    echo ""
    echo "Environment Variables:"
    echo "  HOST                     Bind host address"
    echo "  PORT                     Server port"
    echo ""
    echo "Examples:"
    echo "  # Start with default settings (accessible from all interfaces)"
    echo "  ./scripts/serve_docs.sh"
    echo ""
    echo "  # Bind to localhost only"
    echo "  ./scripts/serve_docs.sh -h 127.0.0.1"
    echo ""
    echo "  # Custom host and port"
    echo "  ./scripts/serve_docs.sh -h 192.168.1.100 -p 9000"
    echo ""
    echo "  # Using environment variables"
    echo "  HOST=localhost PORT=3000 ./scripts/serve_docs.sh"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            show_usage
            exit 1
            ;;
    esac
done

echo "Starting BitVM API Documentation Server..."
echo ""

# Check if documentation exists
if [ ! -d "$DOCS_DIR" ]; then
    echo "Error: Documentation directory does not exist: $DOCS_DIR"
    echo "Please run first: ./scripts/generate_api_docs.sh"
    exit 1
fi

echo "Documentation Directory: $DOCS_DIR"
echo "Server Host: $HOST"
echo "Server Port: $PORT"
echo ""
echo "Access Documentation:"
if [ "$HOST" = "0.0.0.0" ]; then
    echo "  http://localhost:$PORT"
    echo "  http://127.0.0.1:$PORT"
    echo "  Or use your machine's IP address"
else
    echo "  http://$HOST:$PORT"
fi
echo ""
echo "Press Ctrl+C to stop server"
echo ""

cd "$DOCS_DIR"

# Try using Python 3
if command -v python3 &> /dev/null; then
    echo "Starting server with Python 3..."
    python3 -m http.server $PORT --bind $HOST
elif command -v python &> /dev/null; then
    # Check Python version
    PYTHON_VERSION=$(python -c 'import sys; print(sys.version_info[0])')
    if [ "$PYTHON_VERSION" -eq 3 ]; then
        echo "Starting server with Python..."
        python -m http.server $PORT --bind $HOST
    else
        echo " Warning: Python 2 does not support --bind parameter"
        echo "Starting server with Python 2 (binds to 0.0.0.0)..."
        python -m SimpleHTTPServer $PORT
    fi
else
    echo "Error: Python not found"
    echo ""
    echo "Please install Python or use Docker deployment:"
    echo " ./scripts/deploy_docs.sh"
    exit 1
fi
