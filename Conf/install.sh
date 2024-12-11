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

# Attempt to remove the current install of Santa, if any. If this command
# succeeds, Santa is not currently running and this script should finish the
# install. If Santa is running, its tamper protections will prevent removal
# of /Applications/Santa.app.
/bin/rm -rf /Applications/Santa.app >/dev/null 2>&1
if [ $? -eq 0 ]; then
  # Removal was successful.
  # Install Santa and load the system extension. The system extension will
  # finish loading the rest of Santa's configs and helper services.
  /bin/cp -r ${BINARIES}/Santa.app /Applications/
  /Applications/Santa.app/Contents/MacOS/Santa --load-system-extension
else
  # Tamper protections are enabled, ask Santa to install the update. If the
  # update is valid, the system extension will take care of finishing the
  # install.
  /bin/mkdir -p /var/db/santa/migration
  /bin/cp -r ${BINARIES}/Santa.app /var/db/santa/migration/

  # Check if any NPS SigningID rules exist:
  cnt=$(/usr/bin/sqlite3 'file:///var/db/santa/rules.db?immutable=1' 'SELECT COUNT(*) FROM rules WHERE identifier LIKE "ZMCG7MLDV94:%"')
  sb='(version 1)(allow default)(deny mach-lookup (with no-report) (global-name "com.apple.cfprefsd.daemon"))(deny file-read-data (with no-report) (subpath "/Library/Managed Preferences/com.northpolesec.santa.plist"))'

  signing_ids=("ZMCG7MLDV94:com.northpolesec.santa" "ZMCG7MLDV94:com.northpolesec.santa.ctl" "ZMCG7MLDV94:com.northpolesec.santa.syncservice")

  # Add rules to allow the minimum set of NPS Santa components
  for signing_id in "${signing_ids[@]}"; do
    sudo /usr/bin/sandbox-exec -p "${sb}" /Applications/Santa.app/Contents/MacOS/santactl rule --allow --signingid --identifier "${signing_id}" >/dev/null 2>&1
  done

  /Applications/Santa.app/Contents/MacOS/santactl install

  # Cleanup cache dir.
  /bin/rm -rf /var/db/santa/migration

  # If there were previously SigningID rules that existed, leave anything we might've added be, assume the existing rules were correct. Otherwise remove
  if [[ cnt -eq 0 ]]; then
    # After running santactl install, the daemon will reply and unblock the command before
    # continuing to execute the main app to load the new system extension. Give some time
    # for this to happen by sleeping here to make sure the rules aren't removed too soon.
    /bin/sleep 10

    # Cleanup
    for signing_id in "${signing_ids[@]}"; do
      sudo /usr/bin/sandbox-exec -p "${sb}" /Applications/Santa.app/Contents/MacOS/santactl rule --remove --signingid --identifier "${signing_id}" >/dev/null 2>&1
    done
  fi
fi

exit 0
