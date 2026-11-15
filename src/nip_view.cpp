#include "nip/view/HttpServer.h"

#ifndef NIP_UI_DIR
#define NIP_UI_DIR "ui"
#endif

int main() {
    return nip::runInspector(NIP_UI_DIR, 8765);
}
