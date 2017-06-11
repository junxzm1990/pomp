#include "insthandler.h"

// two opds, irreversible
void and_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	// through resdeflist, we could link all the entry 
	// needed to  be resolved together
	switch(get_operand_combine(inst)){
		case dest_register_src_imm:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;
		case dest_expression_src_imm:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);	
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_expression:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);
			break;

		default: 
			assert(0);
			break;
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void or_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	// through resdeflist, we could link all the entry 
	// needed to  be resolved together
	switch(get_operand_combine(inst)){
		case dest_register_src_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_expression:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);
			break;

		case dest_register_src_imm:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;
	
		case dest_expression_src_register:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);	
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_expression_src_imm:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);	
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;
	
		default: 
			assert(0);
			break;
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

// two opds, reversible
// special case : xor eax, eax
void xor_handler(re_list_t *instnode){
	pxor_handler(instnode);
}

void not_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *dst;
	re_list_t re_deflist, re_uselist, re_instlist;
	re_list_t *def, *usedst;
	valset_u tempval;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);

	//	for debugginf use
	print_operand_info(inst->operand_count, dst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);

	switch (dst->type) {
		case op_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			break;
		default:
			assert(0);
			break;
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void neg_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	switch (dst->type) {
		case op_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			break;
		default:
			assert(0);
			break;
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void and_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){

	re_list_t *entry;
	re_list_t *src[NOPD], *dst[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);	
	assert(nuse == 2 && ndef == 1);

	// check here
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;
		
		sign_extend_valset(&vs2, CAST2_USE(src[1]->node)->operand->datatype);

		//reversing the instruction
		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte & vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word & vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword & vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);

		}
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		sign_extend_valset(&vs2, CAST2_USE(src[1]->node)->operand->datatype);
		
		//reversing the instruction
		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte & vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word & vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword & vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);

		}
		assign_def_after_value(dst[0], vt);
		//list_add(&dst[0]->deflist, &deflist->deflist);
		add_to_deflist(dst[0], deflist);
	} 
}


void or_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *src[NOPD], *dst[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);	
	assert(nuse == 2 && ndef == 1);

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		//reversing the instruction
		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte | vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word | vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword | vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);
		}
		assert_val(dst[0], vt, false);
	
	}
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		//reversing the instruction
		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte | vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word | vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword | vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);

		}
		assign_def_after_value(dst[0], vt);
		//list_add(&dst[0]->deflist, &deflist->deflist);
		add_to_deflist(dst[0], re_deflist);
	} 
}


void xor_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	pxor_resolver(inst, re_deflist, re_uselist);
}


void not_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *src[NOPD], *dst[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	assert(nuse == 1 && ndef == 1);

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = ~vs1.byte;
				break;
			case op_word:
				vt.word = ~vs1.word;
				break;
			case op_dword:
				vt.dword = ~vs1.dword;
				break;
		}
		assert_val(src[0], vt, false);
	}

	if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs2 = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = ~vs2.byte;
				break;
			case op_word:
				vt.word = ~vs2.word;
				break;
			case op_dword:
				vt.dword = ~vs2.dword;
				break;
		}
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		!CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = ~vs1.byte;
				break;
			case op_word:
				vt.word = ~vs1.word;
				break;
			case op_dword:
				vt.dword = ~vs1.dword;
				break;
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}
}


void neg_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *src[NOPD], *dst[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);	
	assert(nuse == 1 && ndef == 1);

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = 0 - vs1.byte;
				break;
			case op_word:
				vt.word = 0 - vs1.word;
				break;
			case op_dword:
				vt.dword = 0 - vs1.dword;
				break;
		}
		assert_val(src[0], vt, false);
	}

	if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs2 = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = 0 - vs2.byte;
				break;
			case op_word:
				vt.word = 0 - vs2.word;
				break;
			case op_dword:
				vt.dword = 0 - vs2.dword;
				break;
		}
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		!CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = 0 - vs1.byte;
				break;
			case op_word:
				vt.word = 0 - vs1.word;
				break;
			case op_dword:
				vt.dword = 0 - vs1.dword;
				break;
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}
}
