#ifndef __HEURISTICS_H__
#define __HEURISTICS_H__


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdis.h>
#include <assert.h>
#include "disassemble.h"
#include "global.h"
#include "access_memory.h"
#include "reverse_log.h"
#include "reverse_exe.h"
#include "inst_opd.h"
#include "re_alias.h"


void val2addr_heuristics(re_list_t* uselist);

void infer_address_from_value(re_list_t* uselist, re_list_t* node);

#endif
