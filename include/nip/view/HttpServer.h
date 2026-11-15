#pragma once

#include <string>

namespace nip {

// Serves the packet inspector on 127.0.0.1. Returns 1 if the socket cannot be opened.
int runInspector(const std::string& uiDirectory, unsigned short port);

}  // namespace nip
