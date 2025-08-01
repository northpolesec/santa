load("@hedron_compile_commands//:refresh_compile_commands.bzl", "refresh_compile_commands")
load("@rules_apple//apple:versioning.bzl", "apple_bundle_version")
load("//:helper.bzl", "run_command")

package(
    default_visibility = ["//:santa_package_group"],
)

licenses(["notice"])

exports_files([
    "LICENSE",
    "Conf/install_services.sh",
    "Conf/com.northpolesec.santa.bundleservice.plist",
    "Conf/com.northpolesec.santa.metricservice.plist",
    "Conf/com.northpolesec.santa.plist",
    "Conf/com.northpolesec.santa.syncservice.plist",
])

exports_files(["LICENSE"])

# The version label for mac_* rules.
apple_bundle_version(
    name = "version",
    build_label_pattern = ".*santa_{release}\\.{build}",
    build_version = "{release}.{build}",
    capture_groups = {
        "release": "\\d{4}\\.\\d+",
        "build": "\\d+",
    },
    fallback_build_label = "santa_9999.1.1",
    short_version_string = "{release}",
)

# Used to detect release builds
config_setting(
    name = "release_build",
    values = {"define": "SANTA_BUILD_TYPE=release"},
    visibility = [":santa_package_group"],
)

# Adhoc signed - provisioning profiles are not used.
# Used for CI runs and dev builds when SIP is disabled.
config_setting(
    name = "adhoc_build",
    values = {"define": "SANTA_BUILD_TYPE=adhoc"},
    visibility = [":santa_package_group"],
)

# Production signed but has get-task-allow
# Used for live debugging with SIP enabled.
config_setting(
    name = "debugger_build",
    values = {"define": "SANTA_BUILD_TYPE=debugger"},
    visibility = [":santa_package_group"],
)

# Used to detect optimized builds
config_setting(
    name = "opt_build",
    values = {"compilation_mode": "opt"},
)

config_setting(
    name = "missing_xcode_16",
    values = {"define": "SANTA_XCODE_VERSION=missing_xcode_16"},
    visibility = [":santa_package_group"],
)

package_group(
    name = "santa_package_group",
    packages = ["//..."],
)

################################################################################
# Loading/Unloading/Reloading
################################################################################
run_command(
    name = "unload",
    cmd = """
/Applications/Santa.app/Contents/MacOS/Santa --unload-system-extension 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist 2>/dev/null
sudo launchctl unload /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist 2>/dev/null
launchctl unload /Library/LaunchAgents/com.northpolesec.santa.plist 2>/dev/null
""",
)

run_command(
    name = "load",
    cmd = """
/Applications/Santa.app/Contents/MacOS/Santa --load-system-extension
sudo launchctl load /Library/LaunchDaemons/com.northpolesec.santa.bundleservice.plist
sudo launchctl load /Library/LaunchDaemons/com.northpolesec.santa.metricservice.plist
sudo launchctl load /Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist
launchctl load /Library/LaunchAgents/com.northpolesec.santa.plist
""",
)

run_command(
    name = "reload",
    srcs = [
        "//Source/gui:Santa",
    ],
    cmd = """
set -e

rm -rf /tmp/bazel_santa_reload
unzip -d /tmp/bazel_santa_reload \
    $${BUILD_WORKSPACE_DIRECTORY}/bazel-out/*$(COMPILATION_MODE)*/bin/Source/gui/Santa.zip >/dev/null
echo "You may be asked for your password for sudo"
sudo BINARIES=/tmp/bazel_santa_reload CONF=$${BUILD_WORKSPACE_DIRECTORY}/Conf \
    $${BUILD_WORKSPACE_DIRECTORY}/Conf/install.sh
rm -rf /tmp/bazel_santa_reload
echo "Time to stop being naughty"
""",
)

################################################################################
# Release rules - used to create a release tarball
################################################################################
genrule(
    name = "release",
    srcs = [
        "//Source/gui:Santa",
        "Conf/install.sh",
        "Conf/uninstall.sh",
        "Conf/com.northpolesec.santa.bundleservice.plist",
        "Conf/com.northpolesec.santa.metricservice.plist",
        "Conf/com.northpolesec.santa.syncservice.plist",
        "Conf/com.northpolesec.santa.plist",
        "Conf/com.northpolesec.santa.newsyslog.conf",
        "Conf/Package/Distribution.xml",
        "Conf/Package/notarization_tool.sh",
        "Conf/Package/package.sh",
        "Conf/Package/package_and_sign.sh",
        "Conf/Package/postinstall",
        "Conf/Package/preinstall",
        "Conf/Package/migration.sh",
        "Conf/com.northpolesec.santa.migration.plist",
    ],
    outs = ["santa-release.tar.gz"],
    cmd = select({
        "//conditions:default": """
        echo "ERROR: Trying to create a release tarball without optimization."
        echo "Please add '-c opt' flag to bazel invocation"
        """,
        ":opt_build": """
      # Extract Santa.zip
      for SRC in $(SRCS); do
        if [ "$$(basename $${SRC})" == "Santa.zip" ]; then
          mkdir -p $(@D)/binaries
          unzip -q $${SRC} -d $(@D)/binaries >/dev/null
        fi
      done

      # Copy config files
      for SRC in $(SRCS); do
        if [[ "$$(dirname $${SRC})" == *"Conf"* ]]; then
          mkdir -p $(@D)/conf
          cp -H $${SRC} $(@D)/conf/
        fi
      done

      # Gather together the dSYMs. Throw an error if no dSYMs were found
      for SRC in $(SRCS); do
        case $${SRC} in
          *santactl.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santactl.dSYM
            ;;
          *santabundleservice.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santabundleservice.dSYM
            ;;
          *santametricservice.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santametricservice.dSYM
            ;;
          *santasyncservice.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/santasyncservice.dSYM
            ;;
          *Santa.app.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/Santa.app.dSYM
            ;;
          *com.northpolesec.santa.daemon.systemextension.dSYM*Info.plist)
            mkdir -p $(@D)/dsym
            cp -LR $$(dirname $$(dirname $${SRC})) $(@D)/dsym/com.northpolesec.santa.daemon.systemextension.dSYM
            ;;
        esac
      done

      # Cause a build failure if the dSYMs are missing.
      if [[ ! -d "$(@D)/dsym" ]]; then
        echo "dsym dir missing: Did you forget to use --apple_generate_dsym?"
        echo "This flag is required for the 'release' target."
        exit 1
      fi

      # Cause a build failure if any of the binaries are not fat with both
      # architectures included.
      for f in \
          MacOS/Santa MacOS/santabundleservice MacOS/santactl \
          MacOS/santametricservice MacOS/santasyncservice \
          Library/SystemExtensions/com.northpolesec.santa.daemon.systemextension/Contents/MacOS/com.northpolesec.santa.daemon; do
        if ! file $(@D)/binaries/Santa.app/Contents/$${f} | grep arm64; then
          echo "ERROR: Missing arm64 slice"
          exit 1
        fi
        if ! file $(@D)/binaries/Santa.app/Contents/$${f} | grep x86_64; then
          echo "ERROR: Missing x86_64 slice"
          exit 1
        fi
      done

      # Update all the timestamps to now. Bazel avoids timestamps to allow
      # builds to be hermetic and cacheable but for releases we want the
      # timestamps to be more-or-less correct.
      find $(@D)/{binaries,conf,dsym} -exec touch {} \\;

      # Create final output tar
      tar -C $(@D) -czpf $(@) binaries dsym conf
    """,
    }),
    heuristic_label_expansion = 0,
)

genrule(
    name = "package-dev",
    srcs = [":release"],
    outs = ["santa-dev.pkg"],
    cmd = """
  tar -xzvf $(<)
  RELEASE_ROOT=. PKG_OUT_DIR=$(@D) BUILD_DEV_DISTRIBUTION_PKG=1 \
    ./conf/package.sh
  """,
)

test_suite(
    name = "unit_tests",
    tests = [
        "//Source/common:unit_tests",
        "//Source/gui:unit_tests",
        "//Source/santactl:unit_tests",
        "//Source/santad:unit_tests",
        "//Source/santametricservice:unit_tests",
        "//Source/santasyncservice:unit_tests",
    ],
)

refresh_compile_commands(
    name = "refresh_compile_commands",
    # Only compile targets under //Source, the :release and other genrule
    # targets cause issues when constructing compile commands for generated
    # code.
    targets = {
        "//Source/...": "",
    },
)
