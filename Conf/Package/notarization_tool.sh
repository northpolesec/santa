#!/bin/bash

# notarytool wrapper

# Expects 2 arguments:
#   - --file
#   - The path to the archive to submit

# Expects 3 environment variables:
#   - NOTARIZATION_KEY_P8: The base64-encoded content of the key
#   - NOTARIZATION_KEY_ID: The key ID
#   - NOTARIZATION_ISSUER_ID: The issuer ID of the key

set -o pipefail

KEY_FILE_PATH=/tmp/notarization_key.p8

echo "${NOTARIZATION_KEY_P8}" | base64 --decode > "${KEY_FILE_PATH}"

readonly CREDS=(
  --key "${KEY_FILE_PATH}"
  --key-id "${NOTARIZATION_KEY_ID}"
  --issuer "${NOTARIZATION_ISSUER_ID}"
)

readonly SUBMIT_OUTPUT=$(/usr/bin/mktemp -t notarytool-submit)
trap 'rm -f "${SUBMIT_OUTPUT}"' EXIT

/usr/bin/xcrun notarytool submit "${2}" --wait -v "${CREDS[@]}" 2>&1 | tee "${SUBMIT_OUTPUT}"
SUBMIT_RC=$?

# `notarytool submit --wait` exits 0 as long as it managed to wait for a verdict,
# including when that verdict is Invalid. Without checking the status the caller
# proceeds to stapling, which then fails with a misleading CloudKit "Record not
# found" -- the ticket is absent because the submission was rejected.
STATUS=$(/usr/bin/grep -E '^ +status: ' "${SUBMIT_OUTPUT}" | /usr/bin/tail -1 | /usr/bin/awk '{print $2}')
SUBMISSION_ID=$(/usr/bin/grep -E '^ +id: ' "${SUBMIT_OUTPUT}" | /usr/bin/tail -1 | /usr/bin/awk '{print $2}')

if [[ ${SUBMIT_RC} -ne 0 || "${STATUS}" != "Accepted" ]]; then
  echo "Notarization of $(/usr/bin/basename "${2}") failed: status=${STATUS:-unknown} rc=${SUBMIT_RC}" >&2

  # The submission log carries Apple's per-issue reasons, which the submit
  # output does not. Apple expires these after a few days, so fetch it now
  # rather than leaving it to be chased later.
  if [[ -n "${SUBMISSION_ID}" ]]; then
    echo "Fetching notarization log for ${SUBMISSION_ID}" >&2
    /usr/bin/xcrun notarytool log "${SUBMISSION_ID}" "${CREDS[@]}" >&2 ||
      echo "Could not retrieve the notarization log for ${SUBMISSION_ID}" >&2
  fi

  exit 1
fi
