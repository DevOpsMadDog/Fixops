#!/bin/bash

set -e

echo "========================================="
echo "FixOps VC Demo - Docker Quick Start"
echo "========================================="
echo ""

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

echo "✅ Docker is installed"
echo ""

echo "📦 Building Docker image (this may take 2-3 minutes)..."
docker build -f Dockerfile.simple -t fixops-demo:latest . --quiet

if [ $? -eq 0 ]; then
    echo "✅ Docker image built successfully"
else
    echo "❌ Docker build failed"
    exit 1
fi

echo ""
echo "========================================="
echo "Choose how to run the demo:"
echo "========================================="
echo "1. Quick Demo (runs demo command and exits)"
echo "2. Interactive Mode (start API server, run commands manually)"
echo ""
read -p "Enter choice (1 or 2): " choice

case $choice in
    1)
        echo ""
        echo "🚀 Running FixOps demo..."
        echo ""
        docker run --rm \
            -v "$(pwd)/demo_decision_outputs:/app/demo_decision_outputs" \
            fixops-demo:latest
        
        echo ""
        echo "========================================="
        echo "✅ Demo completed!"
        echo "========================================="
        echo ""
        echo "Results saved to: ./demo_decision_outputs/decision.json"
        echo ""
        echo "To view results:"
        echo "  cat demo_decision_outputs/decision.json | jq '.'"
        ;;
    
    2)
        echo ""
        echo "🚀 Starting FixOps container in interactive mode..."
        echo ""
        
        docker run -d \
            --name fixops-vc-demo \
            -p 8000:8000 \
            -v $(pwd)/demo_decision_outputs:/app/demo_decision_outputs \
            -v "$(pwd)/demo_decision_inputs:/app/demo_decision_inputs" \
            fixops-demo:latest \
            bash -c "python demo_api_server.py & tail -f /dev/null"
        
        sleep 3
        
        echo "✅ Container started!"
        echo ""
        echo "========================================="
        echo "Available Commands:"
        echo "========================================="
        echo ""
        echo "1. Run the demo:"
        echo "   docker exec fixops-vc-demo python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty"
        echo ""
        echo "2. Test API health:"
        echo "   curl http://localhost:8000/health"
        echo ""
        echo "3. View logs:"
        echo "   docker logs fixops-vc-demo"
        echo ""
        echo "4. Open shell in container:"
        echo "   docker exec -it fixops-vc-demo bash"
        echo ""
        echo "5. Stop container:"
        echo "   docker stop fixops-vc-demo && docker rm fixops-vc-demo"
        echo ""
        echo "API is available at: http://localhost:8000"
        echo ""
        ;;
    
    *)
        echo "Invalid choice. Exiting."
        exit 1
        ;;
esac
