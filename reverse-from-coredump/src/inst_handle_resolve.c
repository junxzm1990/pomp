#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "reverse_exe.h"
#include "inst_opd.h"

/*
void reverse_operation(valset_u *src1, valset_u *src2, valset_u *dst, x86_insn_t) {
}
*/

int translate_datatype_to_byte(enum x86_op_datatype datatype) {
	switch (datatype) {
		case op_byte:
			return 1;
			break;
		case op_word:
			return 2;
			break;
		case op_dword:
			return 4;
			break;
		case op_qword:
			return 8;
			break;
		case op_dqword:
			return 16;
			break;
		case op_ssimd:
			return 16; 
			break; 
		default:
			LOG(stderr, "No such datatype\n");
			assert(0);
	}
}

