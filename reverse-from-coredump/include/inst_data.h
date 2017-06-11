#ifndef __INST_DATA__
#define __INST_DATA__

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include "global.h"



typedef struct memseg_struct{

	unsigned low;
	unsigned high;
	void * data;
}memseg_t; 

typedef struct corereg_struct{
	elf_gregset_t regs;
	long xmm_reg[32];
	unsigned gs_base;		
}corereg_t;


typedef struct coredata_struct{
	size_t memsegnum; 
	memseg_t * coremem; 
	corereg_t corereg;
}coredata_t;

unsigned long load_trace(elf_core_info* core_info, elf_binary_info * binary_info, char *trace_file, x86_insn_t *instlist);

coredata_t * load_coredump(elf_core_info *core_info, elf_binary_info *binary_info);

bool verify_useless_inst(x86_insn_t *inst);

void destroy_instlist(x86_insn_t * instlist);

#endif

