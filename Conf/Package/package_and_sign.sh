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

# Every artifact Santa ships is universal. Checking the slices that happen to be
# present is not enough on its own: a thin binary satisfies a per-slice loop
# trivially, which is how an arm64-only sleigh shipped for several releases.
readonly EXPECTED_ARCHS="x86_64 arm64"

# Verify the architectures of a signed artifact, then the signature, embedded
# Info.plist and signing identity of every slice of it.
#
# `codesign --verify` without --arch only checks the slice matching the host, so
# a broken slice in a universal binary passes locally and is first caught by
# notarization -- which reports it as "The signature of the binary is invalid"
# with no indication of which slice or why. rules_apple 4.4.0 through at least
# 4.5.3 omit the embedded Info.plist from the non-native slice of
# macos_command_line_application, which produces exactly that.
function verify_slices {
  local artifact="${1}"
  local want_id="${2}"
  local binary="${artifact}"

  # Refuse to run without an expected identifier rather than silently checking
  # nothing, which is how a caller would quietly opt out of half this function.
  [[ -n "${want_id}" ]] ||
    die "no expected signing identifier given for ${artifact}"

  if [[ -d "${artifact}" ]]; then
    local exe
    exe=$(/usr/bin/plutil -extract CFBundleExecutable raw -o - \
      "${artifact}/Contents/Info.plist") ||
      die "could not read CFBundleExecutable from ${artifact}"
    binary="${artifact}/Contents/MacOS/${exe}"
  fi

  # Capture the architectures rather than iterating the substitution directly: a
  # failing or empty lipo would otherwise run the loop zero times and report
  # success, which is the one thing a verification step must never do.
  local archs
  archs=$(/usr/bin/lipo -archs "${binary}") ||
    die "could not read the architectures of ${binary}"
  [[ -n "${archs}" ]] || die "lipo reported no architectures for ${binary}"

  local want
  for want in ${EXPECTED_ARCHS}; do
    /usr/bin/grep -qw "${want}" <<<"${archs}" ||
      die "${binary} has no ${want} slice (found: ${archs})"
  done

  local arch details id
  for arch in ${archs}; do
    /usr/bin/codesign --verify --strict --arch "${arch}" "${artifact}" ||
      die "invalid signature in the ${arch} slice of ${artifact}"

    # An unbound Info.plist means the slice carries no plist for its signature
    # to cover. codesign cannot add one; only the linker can.
    details=$(/usr/bin/codesign -d --arch "${arch}" -vvv "${binary}" 2>&1) ||
      die "could not inspect the ${arch} slice of ${binary}"
    if /usr/bin/grep -q "Info.plist=not bound" <<<"${details}"; then
      die "the ${arch} slice of ${binary} has no bound Info.plist"
    fi

    # codesign takes the identifier from the embedded Info.plist's
    # CFBundleIdentifier, falling back to the file name under --prefix, so it
    # is a property of the build rather than of the signing step here.
    id=$(/usr/bin/sed -n 's/^Identifier=//p' <<<"${details}")
    [[ "${id}" == "${want_id}" ]] ||
      die "the ${arch} slice of ${binary} is signed as \"${id}\", expected \"${want_id}\""
  done
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
    --prefix com.northpolesec.santa.
    --generate-entitlement-der
    --options library,kill,runtime
  )

  if [[ "${BN}" == "sleigh" ]]; then
    defaults write "${SCRATCH}/parent-launch-constraints.plist" team-identifier "${SIGNING_TEAMID}"
    CODESIGN_OPTS+=(--launch-constraint-parent "${SCRATCH}/parent-launch-constraints.plist")
  fi

  echo "codesigning ${BN}"
  /usr/bin/codesign "${CODESIGN_OPTS[@]}" "${ARTIFACT}"

  # These are not derivable from the file name -- santactl signs as ".ctl", and
  # the identifiers come from each target's Info.plist. santad matches some of
  # them exactly at runtime, notably kSleighSigningID for the Sleigh database
  # tamper-resistance carve-out, so a drifting identifier revokes access rather
  # than breaking anything visibly.
  case "${BN}" in
    santactl) WANT_ID="com.northpolesec.santa.ctl" ;;
    santabundleservice) WANT_ID="com.northpolesec.santa.bundleservice" ;;
    santametricservice) WANT_ID="com.northpolesec.santa.metricservice" ;;
    santasyncservice) WANT_ID="com.northpolesec.santa.syncservice" ;;
    sleigh) WANT_ID="com.northpolesec.santa.sleigh" ;;
    com.northpolesec.santa.daemon.systemextension) WANT_ID="com.northpolesec.santa.daemon" ;;
    Santa.app) WANT_ID="com.northpolesec.santa" ;;
    *) die "no expected signing identifier for ${BN}" ;;
  esac

  echo "verifying every slice of ${BN}"
  verify_slices "${ARTIFACT}" "${WANT_ID}"
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

################################################################################
# Lite package - strips sleigh and network extension from the app bundle
################################################################################
if [ -n "${BUILD_LITE_PACKAGE}" ]; then
  readonly LITE_RELEASE_NAME="santa-${RELEASE_VERSION}-lite"
  readonly LITE_PKG_PATH="${ARTIFACTS_DIR}/${LITE_RELEASE_NAME}.pkg"

  _lite_root=$(/usr/bin/mktemp -d "${TMPDIR}santa-lite-"XXXXXX) || die "failed to create lite temp directory"
  [[ -n "${_lite_root}" && -d "${_lite_root}" ]] || die "mktemp returned invalid directory: '${_lite_root}'"
  readonly LITE_ROOT="${_lite_root}"
  readonly LITE_APP="${LITE_ROOT}/Santa.app"

  echo "creating lite app bundle"
  /bin/cp -R "${INPUT_APP}" "${LITE_APP}"

  # Remove sleigh and network extension
  /bin/rm -f "${LITE_APP}/Contents/MacOS/sleigh"
  /bin/rm -rf "${LITE_APP}/Contents/Library/SystemExtensions/com.northpolesec.santa.netd.systemextension"

  # Mark the bundle as a Lite edition
  /usr/bin/plutil -insert SNTIsLite -bool YES "${LITE_APP}/Contents/Info.plist"

  # Re-sign the app
  BN=$(/usr/bin/basename "${LITE_APP}")
  echo "codesigning lite ${BN}"
  /usr/bin/codesign \
    --sign "${SIGNING_IDENTITY}" \
    --keychain "${SIGNING_KEYCHAIN}" \
    --preserve-metadata=entitlements \
    --timestamp \
    --force \
    --prefix com.northpolesec.santa. \
    --generate-entitlement-der \
    --options library,kill,runtime \
    "${LITE_APP}"

  echo "verifying every slice of the lite Santa.app"
  verify_slices "${LITE_APP}" "com.northpolesec.santa"

  # Notarize the lite app
  echo "zipping lite Santa.app"
  /usr/bin/zip -9r "${LITE_ROOT}/Santa.app.zip" "${LITE_APP}"

  echo "notarizing lite Santa.app"
  "${NOTARIZATION_TOOL}" --file "${LITE_ROOT}/Santa.app.zip"

  echo "stapling lite Santa.app"
  /usr/bin/xcrun stapler staple -v "${LITE_APP}"

  # Build the lite component pkg
  export RELEASE_ROOT
  export LITE_APP
  export PKG_OUT_DIR="${LITE_ROOT}"
  "${RELEASE_ROOT}/conf/package.sh"

  # Build signed lite distribution package
  echo "productbuild lite pkg"
  /bin/mkdir -p "${LITE_ROOT}/${LITE_RELEASE_NAME}"
  /usr/bin/productbuild \
    --distribution "${RELEASE_ROOT}/conf/Distribution.xml" \
    --package-path "${LITE_ROOT}" \
    --version "${RELEASE_VERSION}" \
    --sign "${INSTALLER_SIGNING_IDENTITY}" --keychain "${INSTALLER_SIGNING_KEYCHAIN}" \
    "${LITE_ROOT}/${LITE_RELEASE_NAME}/${LITE_RELEASE_NAME}.pkg"

  echo "verifying lite pkg signature"
  /usr/sbin/pkgutil --check-signature "${LITE_ROOT}/${LITE_RELEASE_NAME}/${LITE_RELEASE_NAME}.pkg" || die "bad lite pkg signature"

  echo "notarizing lite pkg"
  "${NOTARIZATION_TOOL}" --file "${LITE_ROOT}/${LITE_RELEASE_NAME}/${LITE_RELEASE_NAME}.pkg"

  echo "stapling lite pkg"
  /usr/bin/xcrun stapler staple "${LITE_ROOT}/${LITE_RELEASE_NAME}/${LITE_RELEASE_NAME}.pkg" || die "failed to staple lite pkg"

  echo "copying lite pkg to output"
  cp "${LITE_ROOT}/${LITE_RELEASE_NAME}/${LITE_RELEASE_NAME}.pkg" "${LITE_PKG_PATH}"
fi
