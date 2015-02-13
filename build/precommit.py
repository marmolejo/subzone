#!/usr/bin/env python
# Copyright (c) 2015 The Subzone Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Performs some basic lint checks on the tree. These are done via the cpplint.py
coming from Chromium project and [Cppcheck](http://cppcheck.sourceforge.net).
This script must be run before any commit.
"""
import os
import sys
import re
import subprocess

def Main():
  """Search own project directories for *.cc and *.h files"""
  matches = []
  directories = [ 'crypto', 'net', 'debug' ]

  cc_re = re.compile(r'.+\.(cc|h)$', re.IGNORECASE)

  for dirs in directories:
    for root, dirnames, filenames in os.walk(dirs):
      for name in filenames:
        if cc_re.match(name):
          matches.append(os.path.join(root, name))

  """Run linters against these files"""
  subprocess.call(["third_party/depot_tools/cpplint.py"] + matches)

  subprocess.call(["out/cppcheck", "--enable=all"] + matches)

if __name__ == '__main__':
  sys.exit(Main())
