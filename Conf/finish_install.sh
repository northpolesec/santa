#!/bin/bash

# Move the .app into place, install and load supporting services.
# If a user is logged in, also load the GUI agent.

function die {
  echo "${@}"
  exit 2
}

# CONF_DIR is a required environment variable that points the directory that
# launch job configurations. In the intended use case, CONF_DIR points to the
# running system extension's Resource directory.
[[ -n "${CONF_DIR}" ]] || die "CONF_DIR unset"

# Finish installing the .app.
/bin/rm -rf /Applications/Santa.app
/bin/mv /Applications/Santa_NPS.app /Applications/Santa.app

# Install the launch jobs.
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.plist" "/Library/LaunchAgents/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.bundleservice.plist" "/Library/LaunchDaemons/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.metricservice.plist" "/Library/LaunchDaemons/"
/bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.syncservice.plist" "/Library/LaunchDaemons/"

# Load com.northpolesec.santa.bundleservice
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist

# Load com.northpolesec.santa.metricservice
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist

# Load com.northpolesec.santa.syncservice
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist

GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)
[[ -z "${GUI_USER}" ]] && exit 0

/bin/launchctl asuser "${GUI_USER}" /bin/launchctl load /Library/LaunchAgents/com.northpolesec.santa.plist
exit 0
