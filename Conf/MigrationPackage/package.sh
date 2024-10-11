#!/bin/bash

function die {
  echo "${@}"
  exit 2
}

# This script wraps a release package. It places the release package on disk
# at /Library/Caches/com.northpolesec.santa/santa.pkg. It also installs a
# migration launch daemon, that will wait for certain conditions, then install
# the on-disk release package.
#
# The output of this script is "${PKG_OUT_DIR}/migration.pkg".
#
# If BUILD_DEV_DISTRIBUTION_PKG is set, "santa-dev.pkg" will also be produced.
# The dev package is helpful when testing installer behavior for dev builds.
#
# All of the following environment variables are required.

# The release package the migration package will wrap.
[[ -n "${RELEASE_PACKAGE}" ]] || die "RELEASE_PACKAGE unset"

# PKG_OUT_DIR is a required environment variable that points to a desired
# output directory.
[[ -n "${PKG_OUT_DIR}" ]] || die "PKG_OUT_DIR unset"

# APP_VERSION Santa's app version.
[[ -n "${APP_VERSION}" ]] || die "APP_VERSION unset"

################################################################################

readonly SCRATCH=$(/usr/bin/mktemp -d "${TMPDIR}santa-"XXXXXX)
readonly APP_PKG_ROOT="${SCRATCH}/app_pkg_root"
readonly APP_PKG_SCRIPTS="${SCRATCH}/pkg_scripts"

readonly SCRIPT_PATH="$(/usr/bin/dirname -- ${BASH_SOURCE[0]})"

/bin/mkdir -p "${APP_PKG_ROOT}" "${APP_PKG_SCRIPTS}"

echo "creating migration pkg"

/bin/mkdir -p "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa" \
  "${APP_PKG_ROOT}/Library/LaunchDaemons"
/bin/cp -vX "${RELEASE_PACKAGE}" "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa/santa.pkg"
/bin/cp -vX "conf/migration/com.northpolesec.santa.migration.plist" "${APP_PKG_ROOT}/Library/LaunchDaemons/"
/bin/cp -vX "conf/migration/migration.sh" "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa/"
/bin/cp -vXL "${SCRIPT_PATH}/preinstall" "${APP_PKG_SCRIPTS}/"
/bin/cp -vXL "${SCRIPT_PATH}/postinstall" "${APP_PKG_SCRIPTS}/"
/bin/chmod +x "${APP_PKG_SCRIPTS}/"*

# Disable bundle relocation.
/usr/bin/pkgbuild --analyze --root "${APP_PKG_ROOT}" "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsRelocatable -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsVersionChecked -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleOverwriteAction -string upgrade "${SCRATCH}/component.plist"
/usr/bin/plutil -replace ChildBundles -json "[]" "${SCRATCH}/component.plist"

# Build migration package
/usr/bin/pkgbuild --identifier "com.northpolesec.santa.migration" \
  --version "${APP_VERSION}" \
  --root "${APP_PKG_ROOT}" \
  --component-plist "${SCRATCH}/component.plist" \
  --scripts "${APP_PKG_SCRIPTS}" \
  "${PKG_OUT_DIR}/migration.pkg"

# Build dev distribution package if instructed.
if [ -n "${BUILD_DEV_DISTRIBUTION_PKG}" ]; then
  echo "productbuild pkg"
  /usr/bin/productbuild \
    --distribution "${SCRIPT_PATH}/Distribution.xml" \
    --package-path "${PKG_OUT_DIR}" \
    "${PKG_OUT_DIR}/santa-dev.pkg"
fi

