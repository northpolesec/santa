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
  /Applications/Santa.app/Contents/MacOS/santactl install
  # Cleanup cache dir.
  /bin/rm -rf /var/db/santa/migration
fi

exit 0
