#ifndef __RE_ALIAS_H__
#define __RE_ALIAS_H__

#include <stdbool.h>
#include "elf_core.h"
#include "list.h"
#include "inst_data.h"
#include "reverse_exe.h"
#include "insthandler.h"


enum addrstat{
	NBaseNIndex = 0,
	UBase,  
	UIndex,
	KBaseUIndex,
	UBaseKIndex, 
	UBaseUIndex,
	KBaseKIndex
};

#define REC_ADD 0
#define REC_DEC 1
#define REC_LIM 2


enum addrstat exp_addr_status(re_list_t* base, re_list_t * index);

bool assert_val(re_list_t *node, valset_u vt, bool before);

void assert_address();

re_list_t *find_current_inst(re_list_t *listhead);

re_list_t *get_exp_by_element(re_list_t *elem);

bool ok_to_check_alias(re_list_t *exp);

void continue_exe_with_alias();
#endif
