// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_DEBUG_HEXDUMP_H_
#define BASE_DEBUG_HEXDUMP_H_

#include "base/strings/string_piece.h"

namespace base {
namespace debug {

class Hexdump {
 public:
 	Hexdump(base::StringPiece sp);

  friend std::ostream& operator<< (std::ostream& stream, const Hexdump& hd);

 private:
 	std::string contents_;
};

}  // namespace debug
}  // namespace base

#endif  // BASE_DEBUG_HEXDUMP_H_