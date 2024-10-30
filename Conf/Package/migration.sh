#!/bin/bash

while true;
do
  GOOGLE_SANTA_ACTIVATED="$(/usr/bin/systemextensionsctl list com.apple.system_extension.endpoint_security |
                            /usr/bin/grep -E '^.+EQHXZ8M8AV.+com\.google\.santa\.daemon.+activated.+$')"
  if [ -z "${GOOGLE_SANTA_ACTIVATED}" ]; then
    break;
  else
    sleep 10
  fi
done

# Remove Google Santa's services and on-disk artifacts.
/bin/launchctl remove com.google.santa.bundleservice || true
/bin/launchctl remove com.google.santa.metricservice || true
/bin/launchctl remove com.google.santa.syncservice || true
GUI_USER=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "${GUI_USER}" ]] && /bin/launchctl asuser "${GUI_USER}" /bin/launchctl remove com.google.santa || true
/bin/rm -rf /Applications/Santa.app
/bin/rm -f /Library/LaunchAgents/com.google.santa.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.bundleservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.metricservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.syncservice.plist
/bin/rm -f /private/etc/asl/com.google.santa.asl.conf
# Move Google's newsyslog config file in case any changes were made so that the
# same configuration continues to apply.
/bin/mv -f /private/etc/newsyslog.d/com.google.santa.newsyslog.conf /private/etc/newsyslog.d/com.northpolesec.santa.newsyslog.conf || true

# Install NPS Santa.
/bin/mv /Library/Caches/com.northpolesec.santa/Santa.app /Applications/Santa.app
/Applications/Santa.app/Contents/MacOS/Santa --load-system-extension

# Cleanup migration service and on-disk artifacts.
/bin/rm -rf /Library/Caches/com.northpolesec.santa/
/bin/rm /Library/LaunchDaemons/com.northpolesec.santa.migration.plist
/bin/launchctl remove com.northpolesec.santa.migration

exit 0
