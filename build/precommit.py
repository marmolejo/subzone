#!/usr/bin/env python
# Copyright (c) 2015 The Subzone Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Performs some basic lint checks on the tree.
"""
import os
import sys
import re
import subprocess

def Main():
  """Search crypto and net directories for *.cc and *.h files"""
  matches = []
  directories = [ 'crypto', 'net' ]

  cc_re = re.compile(r'.+\.(cc|h)$', re.IGNORECASE)

  for dirs in directories:
    for root, dirnames, filenames in os.walk(dirs):
      for name in filenames:
        if cc_re.match(name):
          matches.append(os.path.join(root, name))

  """Run linters against these files"""
  subprocess.call(["/home/zeus/opt/depot_tools/cpplint.py"] + matches)
  subprocess.call(["/home/zeus/bin/cppcheck", "--enable=all"] + matches)

if __name__ == '__main__':
  sys.exit(Main())
