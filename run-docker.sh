#!/bin/bash

# Docker run script for Subdomain Risk Assessment Tool
# Usage: ./run-docker.sh [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default values
SUBDOMAINS_FILE=""
OUTPUT_FILE=""
THREADS=50
TIMEOUT=10
MIN_SCORE=0
DOCKER_IMAGE="subdomain-recon"
CONTAINER_NAME="recon-$(date +%s)"

# Function to display usage
usage() {
    echo -e "${CYAN}Docker Subdomain Risk Assessment Tool${NC}"
    echo ""
    echo "Usage: $0 -f <subdomains_file> [options]"
    echo ""
    echo "Required:"
    echo "  -f, --file <file>       Path to subdomains file"
    echo ""
    echo "Optional:"
    echo "  -o, --output <file>     Output JSON file name (default: results-TIMESTAMP.json)"
    echo "  -t, --threads <num>     Number of threads (default: 50)"
    echo "  --timeout <sec>         Request timeout (default: 10)"
    echo "  --min-score <num>       Minimum score to display (default: 0)"
    echo "  -h, --help             Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 -f subdomains.txt"
    echo "  $0 -f subdomains.txt -o my-results.json -t 30"
    echo "  $0 -f subdomains.txt --timeout 15 --min-score 20"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            SUBDOMAINS_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --min-score)
            MIN_SCORE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$SUBDOMAINS_FILE" ]; then
    echo -e "${RED}Error: Subdomains file is required${NC}"
    usage
fi

# Check if subdomains file exists
if [ ! -f "$SUBDOMAINS_FILE" ]; then
    echo -e "${RED}Error: File '$SUBDOMAINS_FILE' not found${NC}"
    exit 1
fi

# Set default output file if not provided
if [ -z "$OUTPUT_FILE" ]; then
    OUTPUT_FILE="results-$(date +%Y%m%d_%H%M%S).json"
fi

# Create directories
mkdir -p input output

# Copy subdomains file to input directory
cp "$SUBDOMAINS_FILE" input/subdomains.txt

echo -e "${CYAN}Building Docker image...${NC}"
docker build -t $DOCKER_IMAGE .

echo -e "${GREEN}Starting subdomain risk assessment...${NC}"
echo -e "${YELLOW}Configuration:${NC}"
echo "  - Subdomains file: $SUBDOMAINS_FILE"
echo "  - Output file: $OUTPUT_FILE"
echo "  - Threads: $THREADS"
echo "  - Timeout: ${TIMEOUT}s"
echo "  - Min score: $MIN_SCORE"
echo ""

# Run the container
docker run --rm \
    --name "$CONTAINER_NAME" \
    -v "$(pwd)/input:/app/input:ro" \
    -v "$(pwd)/output:/app/output:rw" \
    $DOCKER_IMAGE \
    -f /app/input/subdomains.txt \
    -o /app/output/$OUTPUT_FILE \
    -t $THREADS \
    --timeout $TIMEOUT \
    --min-score $MIN_SCORE

# Check if output file was created
if [ -f "output/$OUTPUT_FILE" ]; then
    echo -e "${GREEN}Results saved to: output/$OUTPUT_FILE${NC}"
else
    echo -e "${YELLOW}No output file generated${NC}"
fi

echo -e "${GREEN}Analysis complete!${NC}"
