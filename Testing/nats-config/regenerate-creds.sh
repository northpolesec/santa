#!/bin/bash
# Script to regenerate NATS credentials with proper permissions

# Set up the operator
export NKEYS_PATH="/tmp/nats-test-keys"
export NSC_HOME="/tmp/nats-test-nsc"

# Clean up any existing data
rm -rf "$NKEYS_PATH" "$NSC_HOME"

# Initialize nsc with the operator
echo "Initializing NSC with santa-operator..."
nsc add operator --name santa-operator --force || true

# Set the operator context
nsc env -o santa-operator

# Create the santa account
echo "Creating santa account..."
nsc add account --name santa || true

# Create the test-machine client user with santa.host.* and santa.tag.* wildcards
echo "Creating ABCDEF123456 user with proper permissions..."
nsc add user --name ABCDEF123456 --account santa \
  --allow-pub "_INBOX.>" \
  --allow-sub "_INBOX.>" \
  --allow-sub "santa.host.*" \
  --allow-sub "santa.tag.*" \
  --allow-sub "santa-clients" \
  --allow-sub "workshop"

# Create the test-publisher user with publishing permissions
echo "Creating test-publisher user with proper permissions..."
nsc add user --name test-publisher --account santa \
  --allow-pub "santa.host.*" \
  --allow-pub "santa.tag.*" \
  --allow-sub "santa.*"

# Generate the credential files
echo "Generating credential files..."
nsc generate creds --account santa --name ABCDEF123456 > ABCDEF123456.creds.new
nsc generate creds --account santa --name test-publisher > test-publisher.creds.new

# Extract the JWT tokens for the header file
echo "Extracting JWT tokens..."
TEST_MACHINE_JWT=$(cat ABCDEF123456.creds.new | grep -A1 "BEGIN NATS USER JWT" | grep -v "BEGIN" | tr -d '\n' | tr -d '-')
TEST_MACHINE_SEED=$(cat ABCDEF123456.creds.new | grep -A1 "BEGIN USER NKEY SEED" | tail -n1 | tr -d '-' | tr -d '\n')

TEST_PUBLISHER_JWT=$(cat test-publisher.creds.new | grep -A1 "BEGIN NATS USER JWT" | grep -v "BEGIN" | tr -d '\n' | tr -d '-')
TEST_PUBLISHER_SEED=$(cat test-publisher.creds.new | grep -A1 "BEGIN USER NKEY SEED" | tail -n1 | tr -d '-' | tr -d '\n')

# Update the test-credentials.h file
cat > test-credentials.h.new <<EOF
#ifndef TEST_CREDENTIALS_H
#define TEST_CREDENTIALS_H

// Test credentials for NATS integration tests
// Generated with santa.host.* and santa.tag.* wildcards

#define TEST_JWT "$TEST_MACHINE_JWT"
#define TEST_SEED "$TEST_MACHINE_SEED"

#define TEST_PUBLISHER_JWT "$TEST_PUBLISHER_JWT"
#define TEST_PUBLISHER_SEED "$TEST_PUBLISHER_SEED"

#endif // TEST_CREDENTIALS_H
EOF

echo "New credential files generated:"
echo "  - ABCDEF123456.creds.new"
echo "  - test-publisher.creds.new"
echo "  - test-credentials.h.new"
echo ""
echo "To apply the changes:"
echo "  cp ABCDEF123456.creds.new test-machine-12345.creds"
echo "  cp test-publisher.creds.new test-publisher.creds"
echo "  cp test-credentials.h.new test-credentials.h"