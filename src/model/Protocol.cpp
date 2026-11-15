#include "nip/model/Protocol.h"

namespace nip {

const char* toString(Protocol protocol) noexcept {
    switch (protocol) {
    case Protocol::Unknown:
        return "Unknown";
    case Protocol::IPv4:
        return "IPv4";
    case Protocol::IPv6:
        return "IPv6";
    case Protocol::Tcp:
        return "TCP";
    case Protocol::Udp:
        return "UDP";
    case Protocol::Icmp:
        return "ICMP";
    }
    return "Unknown";
}

}  // namespace nip
