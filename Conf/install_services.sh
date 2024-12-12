#!/bin/bash

# This script is run by the NPS Santa sysx (com.northpolesec.santa.daemon) on
# sysx startup, before tamper protections are brought up.

function die {
  echo "${@}"
  exit 2
}

# CONF_DIR is a required environment variable that points the directory that
# contains NPS Santa launch job configurations. In the intended use case,
# CONF_DIR points to the com.northpolesec.santa.daemon Resource directory.
[[ -n "${CONF_DIR}" ]] || die "CONF_DIR unset"

################################################################################

#
# Migration support.
#

# Remove unsupported versions of Santa.
/bin/launchctl remove com.google.santa.bundleservice || true
/bin/launchctl remove com.google.santa.metricservice || true
/bin/launchctl remove com.google.santa.syncservice || true
/bin/launchctl remove com.google.santad || true
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.google.santa || true
/bin/rm /Library/LaunchAgents/com.google.santa.plist
/bin/rm /Library/LaunchDaemons/com.google.santa.bundleservice.plist
/bin/rm /Library/LaunchDaemons/com.google.santa.metricservice.plist
/bin/rm /Library/LaunchDaemons/com.google.santa.syncservice.plist
/bin/rm /Library/LaunchDaemons/com.google.santad.plist
# Move Google's newsyslog config file in case any changes were made so that the
# same configuration continues to apply.
/bin/mv -f /private/etc/newsyslog.d/com.google.santa.newsyslog.conf /private/etc/newsyslog.d/com.northpolesec.santa.newsyslog.conf || true

################################################################################

# Remove lingering migration launchd plist. This can stick around when upgrading
# NPS Santa due to tamper protections of the previous version of NPS preventing
# the deletion. While this is benign, we can take the opportunity to remove the
# artifact here.
/bin/rm -f /Library/LaunchDaemons/com.northpolesec.santa.migration.plist
/bin/rm -f /Library/LaunchDaemons/com.northpolesec.santa-migration.plist

# Unload NPS Santa services in preparation for installation / update.
/bin/launchctl remove com.northpolesec.santa.bundleservice || true
/bin/launchctl remove com.northpolesec.santa.metricservice || true
/bin/launchctl remove com.northpolesec.santa.syncservice || true
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
