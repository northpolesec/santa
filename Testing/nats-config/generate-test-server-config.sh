#!/bin/bash
# Generate a test NATS server configuration that accepts the test credentials

cat > nats-test-server.conf <<EOF
# Simple NATS server config for testing
# No authentication required for local testing

port: 4222
host: 0.0.0.0

# Allow any connection for testing
authorization {
  default_permissions {
    publish = ">"
    subscribe = ">"
  }
}

# Logging
log_file: "/tmp/nats-test-server.log"
debug: true
trace: true

# System account for monitoring (optional)
system_account: SYS

accounts {
  SYS {
    users = [
      { user: "sys", password: "sys" }
    ]
  }
  
  SANTA {
    users = [
      # Test machine user
      { 
        user: "test-machine-12345",
        password: "test",
        permissions: {
          publish: ["_INBOX.>"]
          subscribe: ["_INBOX.>", "santa-clients", "santa.*", "workshop"]
        }
      },
      # Test publisher user  
      {
        user: "test-publisher",
        password: "test",
        permissions: {
          publish: ">"
          subscribe: ">"
        }
      }
    ]
  }
}

EOF

echo "Generated nats-test-server.conf for testing"
echo "To use: nats-server -c nats-test-server.conf"