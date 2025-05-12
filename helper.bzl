"""This module defines some helper rules."""

load("@build_bazel_rules_apple//apple:macos.bzl", "macos_unit_test")
load("@build_bazel_rules_apple//apple:resources.bzl", "apple_resource_group")
load("@build_bazel_rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_cc//cc:defs.bzl", "objc_library")

def run_command(name, cmd, **kwargs):
    """A rule to run a command."""
    native.genrule(
        name = "%s__gen" % name,
        executable = True,
        outs = ["%s.sh" % name],
        cmd = "echo '#!/bin/bash' > $@ && echo '%s' >> $@" % cmd,
        **kwargs
    )
    sh_binary(
        name = name,
        srcs = ["%s.sh" % name],
    )

def santa_unit_test(
        name,
        srcs = [],
        deps = [],
        data = [],
        size = "medium",
        minimum_os_version = "13.0",
        resources = [],
        structured_resources = [],
        copts = [],
        **kwargs):
    apple_resource_group(
        name = "%s_resources" % name,
        resources = resources,
        structured_resources = structured_resources,
    )

    objc_library(
        name = "%s_lib" % name,
        testonly = 1,
        srcs = srcs,
        deps = deps,
        copts = copts,
        data = data + [":%s_resources" % name],
        **kwargs
    )

    macos_unit_test(
        name = "%s" % name,
        bundle_id = "com.northpolesec.santa.UnitTest.%s" % name,
        minimum_os_version = minimum_os_version,
        deps = [":%s_lib" % name],
        size = size,
        visibility = ["//:__subpackages__"],
    )
