// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUG_HEXDUMP_H_
#define DEBUG_HEXDUMP_H_

#include "base/strings/string_piece.h"

#define h(var) hexdump(#var, var)

// This helper function does a 'hexdump' of the string passed as second
// argument. Very useful for debugging purposes.
void hexdump(base::StringPiece label, base::StringPiece sp);

#endif  // DEBUG_HEXDUMP_H_
