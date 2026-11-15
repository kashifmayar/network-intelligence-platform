#pragma once

#include "nip/byte/ByteView.h"
#include "nip/model/Headers.h"
#include "nip/model/ParseResult.h"

namespace nip {

struct IPv4Parse {
    IPv4Header header;
    // Bytes after the IPv4 header, limited to the total-length field when the
    // captured buffer is longer than that field. Not a transport parse.
    ByteView payload;
};

// Parses an IPv4 header, including a variable options region. A non-initial
// fragment is still a successful IPv4 parse; this function does not read a
// transport header.
ParseResult<IPv4Parse> parseIPv4(ByteView packet);

}  // namespace nip
