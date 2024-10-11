#!/bin/bash

# This script is run by the NPS Santa sysx (com.northpolesec.santa.daemon) on
# sysx startup, if there is a staged NPS Santa install pending, and the Google
# Santa sysx (com.google.santa.daemon) has been removed.
# The script removes the rest of Google Santa's services and on-disk
# artifacts, then finishes installing NPS Santa.

function die {
  echo "${@}"
  exit 2
}

[[ -d "/Applications/Santa_NPS.app" ]] || die "no staged install"

# CONF_DIR is a required environment variable that points the directory that
# contains NPS Santa launch job configurations. In the intended use case,
# CONF_DIR points to the com.northpolesec.santa.daemon Resource directory.
[[ -n "${CONF_DIR}" ]] || die "CONF_DIR unset"

################################################################################

# Remove Google Santa's services and on-disk artifacts.
/bin/launchctl remove com.google.santa.bundleservice || true
/bin/launchctl remove com.google.santa.metricservice || true
/bin/launchctl remove com.google.santa.syncservice || true
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.google.santa || true
/bin/rm -f /Library/LaunchAgents/com.google.santa.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.bundleservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.metricservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.syncservice.plist
/bin/rm -f /private/etc/asl/com.google.santa.asl.conf
/bin/rm -f /private/etc/newsyslog.d/com.google.santa.newsyslog.conf

################################################################################

# Unload NPS Santa services in preparation for the update.
/bin/launchctl remove com.northpolesec.santa.bundleservice || true
/bin/launchctl remove com.northpolesec.santa.metricservice || true
/bin/launchctl remove com.northpolesec.santa.syncservice || true
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.northpolesec.santa || true

# Finish installing NPS Santa.
/bin/rm -rf /Applications/Santa.app 
/bin/mv /Applications/Santa_NPS.app /Applications/Santa.app

# Create a symlink for santactl.
mkdir -p /usr/local/bin
/bin/ln -sf /Applications/Santa.app/Contents/MacOS/santactl /usr/local/bin/santactl

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
