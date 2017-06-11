#ifndef __RE_STACKPOINTER__
#define __RE_STACKPOINTER__

#include <libdis.h>
#include <stdbool.h>
#include "reverse_exe.h"

#define MOVEBPESP 1
#define RETADDR   2

re_list_t * check_esp_known_of_inst(re_list_t *inst);

void resolve_esp();
#endif
