#!/usr/bin/env python
# Copyright (c) 2015 The Subzone Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""
Clones a GIT repository into a directory and checks out a specified revision.
It takes 3 arguments: (src, rev, dst). |src| is the URL for the GIT repository
to clone, |rev| the changeset id, |dst| the destination directory.
"""

import os
import sys

def Main(src, rev, dst):
  if not os.path.isdir(dst):
    os.system('git clone ' + src + ' ' + dst)
    os.system('git reset --hard ' + rev)


if __name__ == '__main__':
  sys.exit(Main(sys.argv[1], sys.argv[2], sys.argv[3]))
