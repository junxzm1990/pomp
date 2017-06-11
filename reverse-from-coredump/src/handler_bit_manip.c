#include "insthandler.h"

void bittest_handler(re_list_t * instnode){
	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def,*usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	convert_offset_to_exp(src);
	convert_offset_to_exp(dst);	

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	switch(get_operand_combine(inst)){
		case dest_register_src_expression:
			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);
			break;

		case dest_register_src_register:
			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);
			break;
	}
	
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void bitset_handler(re_list_t * instnode){
	assert(0);
}


void bitclear_handler(re_list_t * instnode){
	assert(0);
}


void bsr_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist) {

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt, vt1;
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);
	assert(CAST2_DEF(dst[0]->node)->operand->datatype == op_dword);

	vt1 = CAST2_USE(src[0]->node)->val;

	switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
		case op_word:
			assert(0);
			break;
		case op_dword:
			vt.dword = DWORD_SIZE - 1 - __builtin_clzl(vt1.dword);
			break;
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}
}


void bsf_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist) {

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt, vt1;
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);
	assert(CAST2_DEF(dst[0]->node)->operand->datatype == op_dword);

	vt1 = CAST2_USE(src[0]->node)->val;

	switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
		case op_word:
			assert(0);
			break;
		case op_dword:
			vt.dword = __builtin_ctzl(vt1.dword);
			break;
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}
}


void bittest_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	x86_insn_t* instruction;

        instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;
	
	if (strcmp(instruction->mnemonic, "bsr") == 0) {
		bsr_resolver(inst, re_deflist, re_uselist);
		return;
	}

	if (strcmp(instruction->mnemonic, "bsf") == 0) {
		bsf_resolver(inst, re_deflist, re_uselist);
		return;
	}

}


void bitset_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void bitclear_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}
