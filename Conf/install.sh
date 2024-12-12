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

  SANTA_VERSION=$(/Applications/Santa.app/Contents/MacOS/santactl version | /usr/bin/awk '/^santad/ { print $3 }')
  SANTA_MODE=$(/Applications/Santa.app/Contents/MacOS/santactl status | /usr/bin/awk '/ *Mode/ { print $3 }')

  # For Santa v2024.10 and v2024.11, create allow rules to unblock upgrades in Lockdown mode
  if [[ ("${SANTA_VERSION}" == "2024.10" || "${SANTA_VERSION}" == "2024.11") && "${SANTA_MODE}" != "Monitor" ]]; then
    sb='(version 1)(allow default)(deny mach-lookup (with no-report) (global-name "com.apple.cfprefsd.daemon"))(deny file-read-data (with no-report) (subpath "/Library/Managed Preferences/com.northpolesec.santa.plist"))'

    signing_ids=(
      "ZMCG7MLDV94:com.northpolesec.santa"
      "ZMCG7MLDV94:com.northpolesec.santa.bundleservice"
      "ZMCG7MLDV94:com.northpolesec.santa.ctl"
      "ZMCG7MLDV94:com.northpolesec.santa.daemon"
      "ZMCG7MLDV94:com.northpolesec.santa.metricservice"
      "ZMCG7MLDV94:com.northpolesec.santa.syncservice"
    )

    # Add rules to allow NPS Santa components
    for signing_id in "${signing_ids[@]}"; do
      /usr/bin/sandbox-exec -p "${sb}" /Applications/Santa.app/Contents/MacOS/santactl rule --allow --signingid --identifier "${signing_id}" >/dev/null 2>&1
    done
  fi

  /Applications/Santa.app/Contents/MacOS/santactl install

  # Cleanup cache dir.
  /bin/rm -rf /var/db/santa/migration
fi

exit 0
