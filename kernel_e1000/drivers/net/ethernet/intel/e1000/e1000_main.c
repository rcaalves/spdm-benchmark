#define E1000_SPDM 1
#define E1000_SPDM_DEMO_PRINT 0

#if E1000_SPDM
#include "e1000_main_spdm.c"
#else
#include "e1000_main_original.c"
#endif