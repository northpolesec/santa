#!/bin/bash
#
# Script to re-generate the base en.lproj localizable strings based on the
# SwiftUI code used to generate the UI, and any helper classes used. After
# generation, it will be necessary to diff the result to see which strings
# need to be added to other localizations.
#
# The output of genstrings is UTF-16, which many tools treat as binary
# (including git), so the output is converted to UTF-8 with iconv.
#

cd "$(dirname "$0")"
genstrings -SwiftUI -u -o $PWD ../../*.swift ../../../common/SNTBlockMessage.m
iconv -f UTF-16 -t UTF-8 $PWD/Localizable.strings > $PWD/Localizable.strings.utf8
mv $PWD/Localizable.strings.utf8 $PWD/Localizable.strings
