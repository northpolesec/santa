#!/usr/bin/env python3
"""Script to verify localization completeness."""

import os
import pathlib
import plistlib
import subprocess


def regen_base_localization():
  """Re-generation the English localization file using genstrings."""
  files_to_localize = [
      f.as_posix() for f in pathlib.Path('Source/gui').glob('*.swift')
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

  os.rename(
      'Localizable.strings.utf8',
      'Source/gui/Resources/en.lproj/Localizable.strings',
  )
  os.unlink('Localizable.strings')


def find_localizations(rootdir):
  """Discover the localizations currently in the source tree."""
  return [
      d
      for d in pathlib.Path(rootdir).glob('*')
      if (d.is_dir() and d.name.endswith('.lproj') and d.name != 'en.lproj')
  ]


def plist_from_lang(lang_dir):
  """Read a localization string file as a plist and return as a dict."""
  filename = os.path.join(lang_dir, 'Localizable.strings')

  try:
    output = subprocess.check_output(
        ['/usr/bin/plutil', '-convert', 'xml1', '-o', '-', filename]
    )
  except subprocess.CalledProcessError:
    print(f'Failed to parse {lang_dir.stem} localization')
    return None

  return plistlib.loads(output)


def main():
  """Entry point."""
  # Re-generate the base localization
  regen_base_localization()

  # Read in the new base
  base_localization = plist_from_lang('Source/gui/Resources/en.lproj')
  if not base_localization:
    raise UserWarning('Failed to parse base localization')

  # Loop over all the discovered localizations
  for lang in find_localizations('Source/gui/Resources'):
    pl = plist_from_lang(lang)
    if not pl:
      print(f'Failed to parse localization {lang.stem}')
      continue

    base_loc_keys = base_localization.keys()
    lang_keys = pl.keys()

    # If the set of keys in the localization doesn't match the base,
    # print an error showing which keys are missing
    missing_keys = [x for x in base_localization.keys() if x not in pl.keys()]
    extra_keys = [x for x in pl.keys() if x not in base_localization.keys()]

    complete = (len(lang_keys) - len(extra_keys)) / len(base_loc_keys) * 100

    print(f'----- Language {lang.stem} -----')
    print(f'Missing: {len(missing_keys)}, {missing_keys}')
    print(f'Extraneous: {len(extra_keys)}, {extra_keys}')
    print(f'Complete: {complete:.2f}%')


if __name__ == '__main__':
  main()
