#include "insthandler.h"

void sys_handler(re_list_t *instnode){
	x86_insn_t* inst;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	if (strcmp(inst->mnemonic, "sysenter") == 0) {
		sysenter_handler(instnode);
	} else if (strcmp(inst->mnemonic, "rdtsc") == 0) {
		rdtsc_handler(instnode);
	} else {
		assert("Other instruction with type 0xE000" && 0);
	}
}

void halt_handler(re_list_t *instnode){
	assert(0);
}

void in_handler(re_list_t *instnode){
	//assert(0);
}

void out_handler(re_list_t *instnode){
	assert(0);
}

void sysenter_handler(re_list_t *instnode){
	x86_insn_t* inst;
	x86_op_t *eax;
	re_list_t re_deflist, re_uselist, re_instlist;  	

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	eax = x86_implicit_operand_1st(inst);

	add_new_define(eax);

	print_info_of_current_inst(instnode);
}

void rdtsc_handler(re_list_t *instnode) {
	x86_insn_t* inst;
	x86_op_t *eax, *edx;
	re_list_t re_deflist, re_uselist, re_instlist;  	

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	edx = x86_implicit_operand_1st(inst);
	eax = x86_implicit_operand_2nd(inst);

	add_new_define(edx);
	add_new_define(eax);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}

void cpuid_handler(re_list_t *instnode){
	assert(0);
}

void sys_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	x86_insn_t* instruction;

        instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;

	if (strcmp(instruction->mnemonic, "sysenter") == 0) {
		sysenter_resolver(inst, re_deflist, re_uselist);
	} else if (strcmp(instruction->mnemonic, "rdtsc") == 0) {
		rdtsc_resolver(inst, re_deflist, re_uselist);
	} else {
		assert("Other instruction with type 0xE000" && 0);
	}
}

void halt_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}

void in_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	//assert(0);
}

void out_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}

void sysenter_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
}

void rdtsc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
}

void cpuid_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}	
