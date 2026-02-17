#!/bin/bash

# This script signs all of Santa's components, verifies the signatures,
# notarizes all of the components, staples them, packages them up, signs the
# package, notarizes the package, puts the package in a DMG and notarizes the
# DMG. It also outputs a single release tarball.
# All of the following environment variables are required.

set -e

function die {
  echo "${@}"
  exit 2
}

# RELEASE_ROOT is a required environment variable that points to the root
# of a release tarball produced with the :release rule in Santa's
# main BUILD file, or the root of an extracted release dir.
[[ -n "${RELEASE_ROOT}" ]] || die "RELEASE_ROOT unset"

# SIGNING_IDENTITY, SIGNING_TEAMID and SIGNING_KEYCHAIN are required environment
# variables specifying the identity and keychain to pass to the codesign tool
# and the team ID to use for verification.
[[ -n "${SIGNING_IDENTITY}" ]] || die "SIGNING_IDENTITY unset"
[[ -n "${SIGNING_TEAMID}" ]] || die "SIGNING_TEAMID unset"
[[ -n "${SIGNING_KEYCHAIN}" ]] || die "SIGNING_KEYCHAIN unset"

# INSTALLER_SIGNING_IDENTITY and INSTALLER_SIGNING_KEYCHAIN are required
# environment variables specifying the identity and keychain to use when signing
# the distribution package.
[[ -n "${INSTALLER_SIGNING_IDENTITY}" ]] || die "INSTALLER_SIGNING_IDENTITY unset"
[[ -n "${INSTALLER_SIGNING_KEYCHAIN}" ]] || die "INSTALLER_SIGNING_KEYCHAIN unset"

# NOTARIZATION_TOOL is a required environment variable pointing to a wrapper
# tool around the tool to use for notarization. The tool must take 1 flag:
#    --file
#        - pointing at a zip file containing the artifact to notarize
[[ -n "${NOTARIZATION_TOOL}" ]] || die "NOTARIZATION_TOOL unset"

# ARTIFACTS_DIR is a required environment variable pointing at a directory to
# place the output artifacts in.
[[ -n "${ARTIFACTS_DIR}" ]] || die "ARTIFACTS_DIR unset"

################################################################################

# Extract release, if necessary
if [[ -f "${RELEASE_ROOT}" ]]; then
  NEW_RELEASE_ROOT=$(mktemp -dt release_root)
  tar xvzf "${RELEASE_ROOT}" -C "${NEW_RELEASE_ROOT}"
  RELEASE_ROOT=${NEW_RELEASE_ROOT}
fi

readonly INPUT_APP="${RELEASE_ROOT}/binaries/Santa.app"
readonly INPUT_SYSX="${INPUT_APP}/Contents/Library/SystemExtensions/com.northpolesec.santa.daemon.systemextension"
readonly INPUT_SANTACTL="${INPUT_APP}/Contents/MacOS/santactl"
readonly INPUT_SANTABS="${INPUT_APP}/Contents/MacOS/santabundleservice"
readonly INPUT_SANTAMS="${INPUT_APP}/Contents/MacOS/santametricservice"
readonly INPUT_SANTASS="${INPUT_APP}/Contents/MacOS/santasyncservice"
readonly INPUT_SLEIGH="${INPUT_APP}/Contents/MacOS/sleigh"

readonly RELEASE_VERSION="$(/usr/bin/plutil -extract CFBundleShortVersionString raw -o - "${INPUT_APP}/Contents/Info.plist")"
readonly RELEASE_NAME="santa-${RELEASE_VERSION}"

readonly SCRATCH=$(/usr/bin/mktemp -d "${TMPDIR}santa-"XXXXXX)

readonly PKG_PATH="${ARTIFACTS_DIR}/${RELEASE_NAME}.pkg"
readonly DMG_PATH="${ARTIFACTS_DIR}/${RELEASE_NAME}.dmg"
readonly TAR_PATH="${ARTIFACTS_DIR}/${RELEASE_NAME}.tar.gz"

# Sign all of binaries/bundles. Maintain inside-out ordering where necessary
for ARTIFACT in "${INPUT_SANTACTL}" "${INPUT_SANTABS}" "${INPUT_SANTAMS}" "${INPUT_SANTASS}" "${INPUT_SLEIGH}" "${INPUT_SYSX}" "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")

  CODESIGN_OPTS=(
    --sign "${SIGNING_IDENTITY}"
    --keychain "${SIGNING_KEYCHAIN}"
    --preserve-metadata=entitlements
    --timestamp
    --force
    --generate-entitlement-der
    --options library,kill,runtime
  )

  if [[ "${BN}" == "sleigh" ]]; then
    defaults write "${SCRATCH}/parent-launch-constraints.plist" team-identifier "${SIGNING_TEAMID}"
    CODESIGN_OPTS+=(--launch-constraint-parent "${SCRATCH}/parent-launch-constraints.plist")
  fi

  echo "codesigning ${BN}"
  /usr/bin/codesign "${CODESIGN_OPTS[@]}" "${ARTIFACT}"
done

# Notarize all the bundles
for ARTIFACT in "${INPUT_SYSX}" "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")

  echo "zipping ${BN}"
  /usr/bin/zip -9r "${SCRATCH}/${BN}.zip" "${ARTIFACT}"

  echo "notarizing ${BN}"
  PBID=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "${ARTIFACT}/Contents/Info.plist")
  "${NOTARIZATION_TOOL}" --file "${SCRATCH}/${BN}.zip"
done

# Staple the App.
for ARTIFACT in "${INPUT_APP}"; do
  BN=$(/usr/bin/basename "${ARTIFACT}")

  echo "stapling ${BN}"
  /usr/bin/xcrun stapler staple -v "${ARTIFACT}"
done

# Ensure _CodeSignature/CodeResources files have 0644 permissions so they can
# be verified without using sudo.
/usr/bin/find "${RELEASE_ROOT}/binaries" -type f -name CodeResources -exec chmod 0644 {} \;
/usr/bin/find "${RELEASE_ROOT}/binaries" -type d -exec chmod 0755 {} \;
/usr/bin/find "${RELEASE_ROOT}/conf" -type f -name "com.northpolesec.santa*" -exec chmod 0644 {} \;

echo "verifying signatures"
/usr/bin/codesign -vv -R="certificate leaf[subject.OU] = ${SIGNING_TEAMID}" \
  "${RELEASE_ROOT}/binaries/"* || die "bad signature"

echo "creating fresh release tarball"
/bin/mkdir -p "${SCRATCH}/tar_root/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/binaries" "${SCRATCH}/tar_root/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/conf" "${SCRATCH}/tar_root/${RELEASE_NAME}"
/bin/cp -r "${RELEASE_ROOT}/dsym" "${SCRATCH}/tar_root/${RELEASE_NAME}"
/usr/bin/tar -C "${SCRATCH}/tar_root" -czvf "${TAR_PATH}" "${RELEASE_NAME}" || die "failed to create release tarball"

# Create the app pkg at "${SCRATCH}/app.pkg".
export RELEASE_ROOT
export PKG_OUT_DIR="${SCRATCH}"
"${RELEASE_ROOT}/conf/package.sh"

# Build signed distribution package
echo "productbuild pkg"
/bin/mkdir -p "${SCRATCH}/${RELEASE_NAME}"
/usr/bin/productbuild \
  --distribution "${RELEASE_ROOT}/conf/Distribution.xml" \
  --package-path "${SCRATCH}" \
  --version "${RELEASE_VERSION}" \
  --sign "${INSTALLER_SIGNING_IDENTITY}" --keychain "${INSTALLER_SIGNING_KEYCHAIN}" \
  "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg"

echo "verifying pkg signature"
/usr/sbin/pkgutil --check-signature "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" || die "bad pkg signature"

echo "notarizing pkg"
"${NOTARIZATION_TOOL}" --file "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg"

echo "stapling pkg"
/usr/bin/xcrun stapler staple "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" || die "failed to staple pkg"

echo "copying pkg to output"
cp "${SCRATCH}/${RELEASE_NAME}/${RELEASE_NAME}.pkg" "${PKG_PATH}"

echo "wrapping pkg in dmg"
/usr/bin/hdiutil create -fs HFS+ -format UDZO \
    -volname "${RELEASE_NAME}" \
    -ov -imagekey zlib-level=9 \
    -srcfolder "${SCRATCH}/${RELEASE_NAME}/" "${DMG_PATH}" || die "failed to wrap pkg in dmg"

echo "notarizing dmg"
"${NOTARIZATION_TOOL}" --file "${DMG_PATH}"

echo "stapling dmg"
/usr/bin/xcrun stapler staple "${DMG_PATH}" || die "failed to staple dmg"
