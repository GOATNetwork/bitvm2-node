#!/bin/bash

# BitVM Node API Documentation Deployment Script
# Deploy API documentation with Docker

set -e

echo "BitVM Documentation Deployment Script"
echo ""

# Configuration variables
DOCS_SOURCE_DIR="docs/api"
CONTAINER_NAME="${CONTAINER_NAME:-bitvm-docs}"
CONTAINER_PORT="${CONTAINER_PORT:-8080}"

# Show usage
show_usage() {
    echo "Usage:"
    echo "  ./scripts/deploy_docs.sh [options]"
    echo ""
    echo "Options:"
    echo "  -p, --port PORT          Container port [default: 8080]"
    echo "  -n, --name NAME          Container name [default: bitvm-docs]"
    echo "  --help                   Show help information"
    echo ""
    echo "Environment Variables:"
    echo "  CONTAINER_NAME           Docker container name"
    echo "  CONTAINER_PORT           Docker container port"
    echo ""
    echo "Examples:"
    echo "  # Deploy with default settings"
    echo "  ./scripts/deploy_docs.sh"
    echo ""
    echo "  # Deploy with custom port"
    echo "  ./scripts/deploy_docs.sh -p 9000"
    echo ""
    echo "  # Deploy with custom container name"
    echo "  ./scripts/deploy_docs.sh -n my-docs -p 3000"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            CONTAINER_PORT="$2"
            shift 2
            ;;
        -n|--name)
            CONTAINER_NAME="$2"
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

# Check if documentation exists
if [ ! -d "$DOCS_SOURCE_DIR" ]; then
    echo "Error: Documentation directory does not exist: $DOCS_SOURCE_DIR"
    echo "Please run first: ./scripts/generate_api_docs.sh"
    exit 1
fi

# Deploy with Docker
deploy_with_docker() {
    echo "Deploying documentation with Docker..."
    
    # Check if Dockerfile exists
    if [ ! -f "scripts/DocServer_Dockerfile" ]; then
        echo "Creating DocServer_Dockerfile..."
        cat > scripts/DocServer_Dockerfile <<'EOF'
FROM ubuntu:latest

# Install python3 (non-interactive)
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /docs

# Copy documentation files
COPY docs/api /docs

# Expose port
EXPOSE 80

# Start simple HTTP server, bind to all interfaces
CMD ["python3", "-m", "http.server", "80", "--bind", "0.0.0.0"]
EOF
    fi
    
    # Stop and remove existing container if it exists
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo "Stopping existing container: ${CONTAINER_NAME}..."
        docker stop ${CONTAINER_NAME} > /dev/null 2>&1 || true
        echo "Removing existing container: ${CONTAINER_NAME}..."
        docker rm ${CONTAINER_NAME} > /dev/null 2>&1 || true
    fi
    
    # Build Docker image
    echo "Building Docker image..."
    docker build -f scripts/DocServer_Dockerfile -t bitvm-docs:latest .
    
    if [ $? -ne 0 ]; then
        echo "Docker image build failed!"
        exit 1
    fi
    
    echo "Docker image built successfully!"
    
    # Start container
    echo "Starting container: ${CONTAINER_NAME}..."
    docker run -d \
        -p ${CONTAINER_PORT}:80 \
        --name ${CONTAINER_NAME} \
        --restart unless-stopped \
        bitvm-docs:latest
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "Container started successfully!"
        echo ""
        echo "Access documentation at:"
        echo " http://localhost:${CONTAINER_PORT}"
        echo ""
        echo "Useful commands:"
        echo " View logs:        docker logs ${CONTAINER_NAME}"
        echo " Stop container:   docker stop ${CONTAINER_NAME}"
        echo " Start container:  docker start ${CONTAINER_NAME}"
        echo " Remove container: docker rm -f ${CONTAINER_NAME}"
    else
        echo "Failed to start container!"
        exit 1
    fi
}

# Execute deployment
echo "Deployment Configuration:"
echo " Source Directory: $DOCS_SOURCE_DIR"
echo " Container Name:   $CONTAINER_NAME"
echo " Container Port:   $CONTAINER_PORT"
echo ""

deploy_with_docker

echo ""
echo "Deployment complete!"
