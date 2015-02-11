// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_DEBUG_HEXDUMP_H_
#define BASE_DEBUG_HEXDUMP_H_

#include "base/strings/string_piece.h"

#define h(var) hexdump(#var,var)

void hexdump(base::StringPiece label, base::StringPiece sp);

#endif  // BASE_DEBUG_HEXDUMP_H_