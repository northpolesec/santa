#!/bin/bash

# notarytool wrapper

# Expects 1 argument:
#   - The path to the archive to submit

# Expects 3 environment variables:
#   - NOTARIZATION_KEY_P8: The base64-encoded content of the key
#   - NOTARIZATION_KEY_ID: The key ID
#   - NOTARIZATION_ISSUER_ID: The issuer ID of the key

KEY_FILE_PATH=/tmp/notarization_key.p8

echo "${NOTARIZATION_KEY_P8}" | base64 --decode > "${KEY_FILE_PATH}"

/usr/bin/xcrun notarytool submit "${2}" --wait \
  --key "${KEY_FILE_PATH}" --key-id "${NOTARIZATION_KEY_ID}" --issuer "${NOTARIZATION_ISSUER_ID}"
