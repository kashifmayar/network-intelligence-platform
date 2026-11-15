#pragma once

#include "nip/byte/ByteView.h"
#include "nip/model/Headers.h"
#include "nip/model/ParseResult.h"

namespace nip {

struct EthernetParse {
    EthernetHeader header;
    ByteView payload;
};

// Parses one Ethernet II frame. IPv6 and any other EtherType are recognized
// and returned as unsupported. Fewer than 14 bytes is malformed.
ParseResult<EthernetParse> parseEthernet(ByteView frame);

}  // namespace nip
