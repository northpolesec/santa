#!/bin/bash

# Run NATS server with JWT authentication
# Internal port 4222 mapped to host port 443

echo "Starting NATS server with JWT authentication..."
echo "Config file: ./nats-server.conf"
echo "Internal port: 4222, Host port: 443"
echo ""
echo "Test credentials are in: ./test-machine-12345.creds"
echo ""

# Stop and remove existing container if it exists
docker stop nats-jwt 2>/dev/null || true
docker rm nats-jwt 2>/dev/null || true

# Run in Docker
docker run -d \
  --name nats-jwt \
  -p 443:4222 \
  -v $(pwd)/nats-server.conf:/nats-server.conf:ro \
  nats:latest \
  -c /nats-server.conf

echo ""
echo "NATS server started. Check logs with: docker logs nats-jwt"
echo ""
echo "To test connection:"
echo "  nats sub -s nats://localhost:443 --creds ./test-machine-12345.creds 'santa.*'"
echo ""
echo "To stop: docker stop nats-jwt && docker rm nats-jwt"