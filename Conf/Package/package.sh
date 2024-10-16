#!/bin/bash

set -e

function die {
  echo "${@}"
  exit 2
}

# This script packages up Santa and its configs.
# The output is "${PKG_OUT_DIR}/app.pkg".
#
# If BUILD_DEV_DISTRIBUTION_PKG is set, "santa-dev.pkg" will also be produced.
# The dev package is helpful when testing installer behavior for dev builds.
#
# All of the following environment variables are required.

# RELEASE_ROOT is a required environment variable that points to the root
# of an extracted release tarball produced with the :release and :release_driver
# rules in Santa's main BUILD file.
[[ -n "${RELEASE_ROOT}" ]] || die "RELEASE_ROOT unset"

# PKG_OUT_DIR is a required environment variable that points to a desired
# output directory.
[[ -n "${PKG_OUT_DIR}" ]] || die "PKG_OUT_DIR unset"

################################################################################

readonly SCRATCH=$(/usr/bin/mktemp -d "${TMPDIR}santa-"XXXXXX)
readonly APP_PKG_ROOT="${SCRATCH}/app_pkg_root"
readonly APP_PKG_SCRIPTS="${SCRATCH}/pkg_scripts"

/bin/mkdir -p "${APP_PKG_ROOT}" "${APP_PKG_SCRIPTS}"

# Ensure _CodeSignature/CodeResources files have 0644 permissions so they can
# be verified without using sudo.
/usr/bin/find "${RELEASE_ROOT}/binaries" -type f -name CodeResources -exec chmod 0644 {} \;
/usr/bin/find "${RELEASE_ROOT}/binaries" -type d -exec chmod 0755 {} \;
/usr/bin/find "${RELEASE_ROOT}/conf" -type f -name "com.northpolesec.santa*" -exec chmod 0644 {} \;

echo "creating app pkg"
/bin/mkdir -p "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa" \
  "${APP_PKG_ROOT}/Library/LaunchDaemons" \
  "${APP_PKG_ROOT}/private/etc/newsyslog.d"
/bin/cp -vXR "${RELEASE_ROOT}/binaries/Santa.app" "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa/"
/bin/cp -vX "${RELEASE_ROOT}/conf/migration.sh" "${APP_PKG_ROOT}/Library/Caches/com.northpolesec.santa/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.northpolesec.santa.migration.plist" "${APP_PKG_ROOT}/Library/LaunchDaemons/"
/bin/cp -vX "${RELEASE_ROOT}/conf/com.northpolesec.santa.newsyslog.conf" "${APP_PKG_ROOT}/private/etc/newsyslog.d/"
/bin/cp -vXL "${RELEASE_ROOT}/conf/preinstall" "${APP_PKG_SCRIPTS}/"
/bin/cp -vXL "${RELEASE_ROOT}/conf/postinstall" "${APP_PKG_SCRIPTS}/"
/bin/chmod +x "${APP_PKG_SCRIPTS}/"*

# Disable bundle relocation.
/usr/bin/pkgbuild --analyze --root "${APP_PKG_ROOT}" "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsRelocatable -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleIsVersionChecked -bool NO "${SCRATCH}/component.plist"
/usr/bin/plutil -replace BundleOverwriteAction -string upgrade "${SCRATCH}/component.plist"
/usr/bin/plutil -replace ChildBundles -json "[]" "${SCRATCH}/component.plist"

# Build app package
readonly APP_VERSION=$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "${RELEASE_ROOT}/binaries/Santa.app/Contents/Info.plist")
/usr/bin/pkgbuild --identifier "com.northpolesec.santa" \
  --version "${APP_VERSION}" \
  --root "${APP_PKG_ROOT}" \
  --component-plist "${SCRATCH}/component.plist" \
  --scripts "${APP_PKG_SCRIPTS}" \
  "${PKG_OUT_DIR}/app.pkg"

# Build dev distribution package if instructed.
if [ -n "${BUILD_DEV_DISTRIBUTION_PKG}" ]; then
  echo "productbuild pkg"
  /usr/bin/productbuild \
    --distribution "${RELEASE_ROOT}/conf/Distribution.xml" \
    --package-path "${PKG_OUT_DIR}" \
    "${PKG_OUT_DIR}/santa-dev.pkg"
fi
