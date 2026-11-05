// C++ includes the C header directly, so its functions must keep C linkage.
#include "stogas.h"

int main() {
    return stogas_abi_version() == STOGAS_ABI_VERSION ? 0 : 1;
}
