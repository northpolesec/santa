#!/bin/bash

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

if [[ -z "${BINARIES}" || -z "${CONF}" ]]; then
  if [[ -d "binaries" ]]; then
    BINARIES="${PWD}/binaries"
    CONF="${PWD}/conf"
  elif [[ -d "../binaries" ]]; then
    BINARIES="${PWD}/../binaries"
    CONF="${PWD}/../conf"
  else
    echo "Can't find binaries, run install.sh from inside the conf directory" 1>&2
    exit 1
  fi
fi

# Unload santad and scheduled sync job.
/bin/launchctl remove com.northpolesec.santad >/dev/null 2>&1

# Unload bundle service
/bin/launchctl remove com.northpolesec.santa.bundleservice >/dev/null 2>&1

# Unload metric service
/bin/launchctl remove com.northpolesec.santa.metricservice >/dev/null 2>&1

# Unload sync service
/bin/launchctl remove com.northpolesec.santa.syncservice >/dev/null 2>&1

# Unload kext.
/sbin/kextunload -b com.northpolesec.santa-driver >/dev/null 2>&1

# Determine if anyone is logged into the GUI
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)

# Unload GUI agent if someone is logged in.
[[ -n "${GUI_USER}" ]] && \
  /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.northpolesec.santagui
[[ -n "$GUI_USER" ]] && \
  /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.northpolesec.santa

# Cleanup cruft from old versions
/bin/launchctl remove com.northpolesec.santasync >/dev/null 2>&1
/bin/rm /Library/LaunchDaemons/com.northpolesec.santasync.plist >/dev/null 2>&1
/bin/rm /usr/libexec/santad >/dev/null 2>&1
/bin/rm /usr/sbin/santactl >/dev/null 2>&1
/bin/rm -rf /Applications/Santa.app 2>&1
/bin/rm -rf /Library/Extensions/santa-driver.kext 2>&1
/bin/rm /etc/asl/com.northpolesec.santa.asl.conf

# Copy new files.
/bin/mkdir -p /var/db/santa

/bin/cp -r ${BINARIES}/Santa.app /Applications

/bin/mkdir -p /usr/local/bin
/bin/ln -s /Applications/Santa.app/Contents/MacOS/santactl /usr/local/bin 2>/dev/null

/bin/cp ${CONF}/com.northpolesec.santa.plist /Library/LaunchAgents
/bin/cp ${CONF}/com.northpolesec.santa.bundleservice.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.northpolesec.santa.metricservice.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.northpolesec.santa.syncservice.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.northpolesec.santad.plist /Library/LaunchDaemons
/bin/cp ${CONF}/com.northpolesec.santa.newsyslog.conf /etc/newsyslog.d/

# Reload syslogd to pick up ASL configuration change.
/usr/bin/killall -HUP syslogd

# Load com.northpolesec.santa.daemon
/bin/launchctl load /Library/LaunchDaemons/com.northpolesec.santad.plist

# Load com.northpolesec.santa.bundleservice
/bin/launchctl load /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist

# Load com.northpolesec.santa.metricservice
/bin/launchctl load /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist

# Load com.northpolesec.santa.syncservice
/bin/launchctl load /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist

# Load GUI agent if someone is logged in.
[[ -z "${GUI_USER}" ]] && exit 0

/bin/launchctl asuser "${GUI_USER}" /bin/launchctl load -w /Library/LaunchAgents/com.northpolesec.santa.plist
exit 0
