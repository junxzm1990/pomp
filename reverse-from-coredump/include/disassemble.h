#ifndef __DISASSEMBLE__
#define __DISASSEMBLE__

#include <libdis.h>

int disasm_one_inst(char *buf, size_t buf_size, int pos, x86_insn_t *inst);

#endif
