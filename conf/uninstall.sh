#!/bin/bash

# Uninstalls Santa from the boot volume, clearing up everything but logs/configs.
# Unloads the kernel extension, services, and deletes component files.
# If a user is logged in, also unloads the GUI agent.

[ "$EUID" != 0 ] && printf "%s\n" "This requires running as root/sudo." && exit 1

# This will block up to 60 seconds
/Applications/Santa.app/Contents/MacOS/Santa --unload-system-extension

# remove helper XPC services
/bin/launchctl remove com.northpolesec.santa.bundleservice
/bin/launchctl remove com.northpolesec.santa.metricservice
/bin/launchctl remove com.northpolesec.santa.syncservice
sleep 1
user=$(/usr/bin/stat -f '%u' /dev/console)
[[ -n "$user" ]] && /bin/launchctl asuser ${user} /bin/launchctl remove com.northpolesec.santa
# and to clean out the log config, although it won't write after wiping the binary
/usr/bin/killall -HUP syslogd
# delete artifacts on-disk
/bin/rm -rf /Applications/Santa.app
/bin/rm -f /Library/LaunchAgents/com.northpolesec.santa.plist
/bin/rm -f /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist
/bin/rm -f /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist
/bin/rm -f /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist
/bin/rm -f /Library/LaunchAgents/com.google.santa.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.bundleservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.metricservice.plist
/bin/rm -f /Library/LaunchDaemons/com.google.santa.syncservice.plist
/bin/rm -f /private/etc/asl/com.northpolesec.santa.asl.conf
/bin/rm -f /private/etc/newsyslog.d/com.northpolesec.santa.newsyslog.conf
/bin/rm -f /usr/local/bin/santactl # just a symlink

#forget receipt
/usr/sbin/pkgutil --forget com.northpolesec.santa

#uncomment to remove the config file and all databases, log files
#/bin/rm -rf /var/db/santa
#/bin/rm -f /var/log/santa*
exit 0
