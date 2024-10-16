#!/bin/bash

# This script is run by the NPS Santa sysx (com.northpolesec.santa.daemon) on
# sysx startup.

function die {
  echo "${@}"
  exit 2
}

# CONF_DIR is a required environment variable that points the directory that
# contains NPS Santa launch job configurations. In the intended use case,
# CONF_DIR points to the com.northpolesec.santa.daemon Resource directory.
[[ -n "${CONF_DIR}" ]] || die "CONF_DIR unset"

################################################################################

# Unload NPS Santa services in preparation for installation / update.
/bin/launchctl remove com.northpolesec.santa.bundleservice || true
/bin/launchctl remove com.northpolesec.santa.metricservice || true
/bin/launchctl remove com.northpolesec.santa.syncservice || true
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.northpolesec.santa || true

# Install the launch jobs.
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.plist" "/Library/LaunchAgents/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.bundleservice.plist" "/Library/LaunchDaemons/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.metricservice.plist" "/Library/LaunchDaemons/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.syncservice.plist" "/Library/LaunchDaemons/"

# Load the services.
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl load /Library/LaunchAgents/com.northpolesec.santa.plist

exit 0
