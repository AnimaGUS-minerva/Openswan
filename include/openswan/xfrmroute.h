#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct XfrmErouteHandle XfrmErouteHandle;

uintptr_t xfrm_route_add(uintptr_t left, uintptr_t right);

struct XfrmErouteHandle *xfrm_eroute_initialize(void);

void xfrm_eroute_free(struct XfrmErouteHandle *ptr);
