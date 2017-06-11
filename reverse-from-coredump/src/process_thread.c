#include <stdio.h>
#include <libdis.h>
#include "elf_binary.h"
#include "access_memory.h"
#include "disassemble.h"
#include "thread_selection.h"
#include "reverse_log.h"
#include "insthandler.h"

// verify the current instruction is executable
int pc_executable(elf_core_info* core_info, struct elf_prstatus thread){
	int exec = 1;
	Elf32_Addr address; 
	address = thread.pr_reg[EIP]; 
	if (!address_executable(core_info, address)){
		LOG(stdout, "STATE: The PC value 0x%x of thread is illegal\n", (unsigned int)address);
		exec = 0;	
	}
	return exec;
}

// verify whether one operand is legal access
int single_op_legal_access(x86_insn_t *insn, x86_op_t *opd, struct elf_prstatus thread, elf_core_info *core_info){
	// according to index/base register and rw property of operand,
	// identify one operand is legal or not
	int legal = 1;
	Elf32_Addr base, index, target;
	x86_ea_t *exp;

	if (opd->type == op_expression) {
		exp = &opd->data.expression;
		switch (get_expreg_status(opd->data.expression)) {
			case No_Reg:
				return legal;
			case Base_Reg:
				index = 0;
				value_of_register(exp->base.name, &base, thread);
				break;
			case Index_Reg:
				base = 0;
				value_of_register(exp->index.name, &index, thread);
				break;
			case Base_Index_Reg:
				value_of_register(exp->base.name, &base, thread);
				value_of_register(exp->index.name, &index, thread);
				break;
			default:
				assert("No such case" && 0);
				break;
		}

		target = base + index * (unsigned int) exp->scale + exp->disp;

		if (address_segment(core_info, target) < 0){
			legal = 0;
		}

		if ((opd -> access & op_write) && (!address_writable(core_info, target))) {
			legal = 0;
		}
	}
	return legal;
}

// verify whether all the operands are legal access
int op_legal_access(x86_insn_t *insn, struct elf_prstatus thread, elf_core_info* core_info){
	// loop all the operands (not matter implicit or explicit)
	// in the operand list of x86_insn_t
	x86_oplist_t *temp;
	for (temp=insn->operands; temp != NULL; temp=temp->next) {
		if (!single_op_legal_access(insn, &temp->op, thread, core_info)) {
			re_ds.root = &temp->op;
			return 0;
		}
	}
	return 1;
}

void add_essential_implicit_operand(x86_insn_t *inst) {
	// according to instruction type, add essential implicit operand
	// for example, add [esp] operand to push instruction;
	x86_op_t espmem;
	x86_op_t *esp;

	switch (inst->type) {
		case insn_push:
			esp = x86_implicit_operand_1st(inst);
			INIT_ESPMEM(&espmem, op_expression, op_dword, op_write, esp);
			add_new_implicit_operand(inst, &espmem);
			break;
	}
}


// verify whether the current instruction is legal access
int pc_legal_access(elf_core_info* core_info, elf_binary_info *bin_info, struct elf_prstatus thread){
	int legal_access; 
	Elf32_Addr address;
	int offset;
	char inst_buf[INST_LEN];
	x86_insn_t inst; 

	address = thread.pr_reg[EIP];
	offset = get_offset_from_address(core_info, address);

	if ((offset == ME_NMAP) || (offset == ME_NMEM)){
		LOG(stdout, "DEBUG: The offset of this pc cannot be obtained\n");
		return 0;
	}
	
	if (offset == ME_NDUMP){
		if (get_data_from_specified_file(core_info, bin_info, address, inst_buf, INST_LEN) < 0)
            return 0;
	}

	if (offset >= 0)
		get_data_from_core((Elf32_Addr)offset, INST_LEN, inst_buf);
	
	if (disasm_one_inst(inst_buf, INST_LEN, 0, &inst) < 0){
		LOG(stdout, "DEBUG: The PC points to an error position\n");
		return 0;
	}

	LOG(stdout, "Evidence: The PC value is 0x%x\n", (unsigned)address);
	char line[64];
	x86_format_insn(&inst, line, 64, intel_syntax);	
	LOG(stdout, "Evidence: The instruction to which PC points is %s. It Is Illegal Access\n", line);

	add_essential_implicit_operand(&inst);

	if (!op_legal_access(&inst, thread, core_info)){
		return 0;
	}
	return 1; 
}

// verify whether one thread crashes
int is_thread_crash(elf_core_info* core_info, elf_binary_info* bin_info, struct elf_prstatus thread){
	int crash  = 0;

	if (!pc_executable(core_info, thread)){
		crash = 1;
		goto out;
	}

	if (!pc_legal_access(core_info,bin_info, thread)){
		crash = 1;
		goto out;
	}
out:
	return crash;
}

// select the thread that leads to crash
// this will be the first step of analysis
int select_thread(elf_core_info* core_info, elf_binary_info * bin_info){
	int crash_num = -1;
	int thread_num = core_info -> note_info->core_thread.thread_num;
	int i = 0;	
	LOG(stdout, "STATE: Determining The Thread Leading To Crash\n");

    // multiple threads exist		
    for (i=0; i<thread_num; i++){
	    if (is_thread_crash(core_info, bin_info, core_info->note_info->core_thread.threads_status[i])){
		    crash_num = i;
		    break;
	    }
    }

	if (crash_num == -1)
		LOG(stderr, "Error: Could not determine the crash thread\n");
	else
		LOG(stdout, "DEBUG: The number of the crashing thread is %d\n", crash_num);
	return crash_num;
}
