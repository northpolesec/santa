#!/usr/bin/env python3
"""Script to verify localization completeness."""

import os
import pathlib
import plistlib
import subprocess


def base_localization():
  """Re-generate the set of localization keys from the code."""
  files_to_localize = [
      f.as_posix() for f in pathlib.Path('Source/gui').glob('*.swift')
      if f.name not in ['SNTTestGUI.swift']
  ]
  files_to_localize.append('Source/common/SNTBlockMessage.m')

  subprocess.check_call(
      ['/usr/bin/genstrings', '-SwiftUI', '-u'] + files_to_localize
  )

  with open('Localizable.strings.utf8', 'w', encoding='utf-8') as f:
    subprocess.check_call(
        [
            '/usr/bin/iconv',
            '-f',
            'UTF-16',
            '-t',
            'UTF-8',
            'Localizable.strings',
        ],
        stdout=f,
    )
  os.unlink('Localizable.strings')

  try:
    p = plist_from_file('Localizable.strings.utf8').keys()
    return p
  except subprocess.CalledProcessError:
    print(f'Failed to parse {lang_dir.stem} localization')
  finally:
    os.unlink('Localizable.strings.utf8')


def find_localizations(rootdir):
  """Discover the localizations currently in the source tree."""
  return [
      d
      for d in pathlib.Path(rootdir).glob('*')
      if (d.is_dir() and d.name.endswith('.lproj'))
  ]


def plist_from_lang(lang_dir):
  """Read a localization file as a plist and return as a dict."""
  filename = os.path.join(lang_dir, 'Localizable.strings')
  try:
    return plist_from_file(filename)
  except subprocess.CalledProcessError:
    print(f'Failed to parse {lang_dir.stem} localization')
    return None


def plist_from_file(filename):
  """
  Read a localization string file as a plist and return as a dict.

  Raises:
    subprocess.CalledProcessError: if the localization could not be parsed.

  """
  output = subprocess.check_output(
      ['/usr/bin/plutil', '-convert', 'xml1', '-o', '-', filename]
  )
  return plistlib.loads(output)


def main():
  """Entry point."""
  # Generate base localization keys
  base_loc_keys = base_localization()
  if not base_loc_keys:
    raise UserWarning('Failed to parse base localization')

  # Loop over all the discovered localizations
  for lang in find_localizations('Source/gui/Resources'):
    pl = plist_from_lang(lang)
    if not pl:
      print(f'Failed to parse localization {lang.stem}')
      continue

    lang_keys = pl.keys()

    # If the set of keys in the localization doesn't match the base,
    # print an error showing which keys are missing
    missing_keys = [x for x in base_loc_keys if x not in pl.keys()]
    extra_keys = [x for x in pl.keys() if x not in base_loc_keys]

    complete = (len(lang_keys) - len(extra_keys)) / len(base_loc_keys) * 100

    print(f'----- Language {lang.stem} -----')
    print(f'Missing: {len(missing_keys)}, {missing_keys}')
    print(f'Extraneous: {len(extra_keys)}, {extra_keys}')
    print(f'Complete: {complete:.2f}%')


if __name__ == '__main__':
  main()
