#include <stddef.h>
#include <valgrind/memcheck.h>

void stogas_taint(void *bytes, size_t length) {
    VALGRIND_MAKE_MEM_UNDEFINED(bytes, length);
}

void stogas_public(void *bytes, size_t length) {
    VALGRIND_MAKE_MEM_DEFINED(bytes, length);
}

unsigned stogas_under_valgrind(void) {
    return RUNNING_ON_VALGRIND;
}
