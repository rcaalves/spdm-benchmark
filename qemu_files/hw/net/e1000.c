#define E1000_SPDM 1
#define E1000_SPDM_DEMO_PRINT 0 // enables GLOBECOM demo prints

#if E1000_SPDM
#include "e1000_spdm.c"
#else
#include "e1000_original.c"
#endif