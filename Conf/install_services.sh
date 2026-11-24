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

#
# Event log rotation.
#

NEWSYSLOG_CONF="/private/etc/newsyslog.d/com.northpolesec.santa.newsyslog.conf"

# SHA-256 of each newsyslog config that Santa shipped before the current one,
# including Google Santa's, which the migration above renames. When you change
# com.northpolesec.santa.newsyslog.conf, add the hash of the version it replaces.
PREVIOUS_NEWSYSLOG_CONFS=(
  "d29cd01025aef9fe9e7e930550f9ac734a426f960f8c522f6f3b770a908c9dc0" # mode 644, flags NZ
)

# Succeeds if the newsyslog config is missing or is one that Santa shipped
# before. Any other config is the admin's, and installs must not overwrite it.
function newsyslog_conf_is_stale {
  [[ -e "${NEWSYSLOG_CONF}" ]] || return 0
  local sha256
  sha256="$(/usr/bin/shasum -a 256 "${NEWSYSLOG_CONF}" | /usr/bin/awk '{ print $1 }')"
  for previous in "${PREVIOUS_NEWSYSLOG_CONFS[@]}"; do
    [[ "${sha256}" == "${previous}" ]] && return 0
  done
  return 1
}

if newsyslog_conf_is_stale; then
  /bin/cp -vX "${CONF_DIR}/com.northpolesec.santa.newsyslog.conf" "${NEWSYSLOG_CONF}"
fi

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

# Install the santactl zsh completion only into a path that only root can
# change: every directory from /usr/local down must be a root-owned directory on
# the Data volume, not a symlink, not writable by group or others, and without
# an ACL. Check each directory before creating its child, set modes explicitly
# (santad's umask can be 077), and test -L before anything that follows
# symlinks.
zsh_dir="/usr/local/share/zsh/site-functions"
data_dev="$(/usr/bin/stat -f '%d' /System/Volumes/Data)"
for d in /usr/local /usr/local/share /usr/local/share/zsh "${zsh_dir}"; do
  [[ -L "${d}" || -e "${d}" ]] || /bin/mkdir -m 0755 "${d}" || { zsh_dir=""; break; }
  read -r uid mode dev < <(/usr/bin/stat -f '%u %Lp %d' "${d}")
  # ls -lde prints one extra line per ACL entry.
  if [[ -L "${d}" || ! -d "${d}" || "${uid}" != 0 || "${dev}" != "${data_dev}" ]] ||
    (( 8#${mode:-0} & 8#022 )) || [[ "$(/bin/ls -lde "${d}")" == *$'\n'* ]]; then
    zsh_dir=""
    break
  fi
done
# Write a new file and rename it over _santactl, so the existing entry is
# replaced whatever it is. mv stats its target, which follows symlinks, so
# remove a symlink first.
f="${zsh_dir}/_santactl"
if [[ -n "${zsh_dir}" ]]; then
  [[ -L "${f}" ]] && /bin/rm -f "${f}"
  if [[ ! -L "${f}" && ! -d "${f}" ]] && tmp="$(/usr/bin/mktemp "${zsh_dir}/.santactl.XXXXXX")"; then
    /bin/cp -X "${CONF_DIR}/_santactl" "${tmp}" && /bin/chmod 0644 "${tmp}" &&
      /bin/mv -fv "${tmp}" "${f}" || /bin/rm -f "${tmp}"
  fi
fi

# Load the services.
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist
/bin/launchctl load -w /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl load /Library/LaunchAgents/com.northpolesec.santa.plist
