#include "insthandler.h"
#include "reverse_exe.h"

void jmp_handler(re_list_t *instnode){

	x86_insn_t *inst, *previnst;
	x86_op_t *srcopd;
	re_list_t *usesrc;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	valset_u tempval = {0}; 
	
	inst = CAST2_INST(instnode->node)->inst_index + re_ds.instlist;
	previnst = CAST2_INST(instnode->node)->inst_index - 1 + re_ds.instlist;

	print_all_operands(inst);

	srcopd = x86_get_dest_operand(inst); 

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	switch (srcopd->type) {
		case op_relative_far:
			assert(previnst->addr == inst->addr + inst->size + srcopd->data.relative_far);
			break;
		case op_relative_near:
			assert(previnst->addr == inst->addr + inst->size + srcopd->data.relative_near);
			break;
		case op_register:
			usesrc = add_new_use(srcopd, Opd);
			break;
		case op_expression:
			usesrc = add_new_use(srcopd, Opd);
			split_expression_to_use(srcopd);
			break;
		default:
			assert(0);
			break;
	}

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}


void jmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	x86_insn_t *previnst;
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *espmemuse;
	int nuse, ndef;
	valset_u vt = {0};

	previnst = CAST2_INST(inst->node)->inst_index - 1 + re_ds.instlist;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert((nuse == 1) || (nuse == 0));

	if (nuse == 0) return;
	
	if (ADDRESS_SIZE == 32) {
		vt.dword = previnst->addr;
	} else {
		assert(0);
	}
	if (!CAST2_USE(src[0]->node)->val_known) {
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}
}


void jcc_handler(re_list_t *instnode){

	x86_insn_t* inst;
	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "ja") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jne") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jnz") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jle") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jz") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jnc") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jc") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jbe") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jg") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jge") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "js") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jns") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jl") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jpe") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jcxz") == 0){
		return;
	}

	assert(0);
}


void jcc_resolver(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist) {

	x86_insn_t* inst;
	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "ja") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jne") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jnz") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jle") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jz") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jnc") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jc") == 0){
		return;
	}

	if (strcmp(inst->mnemonic, "jbe") == 0){
		return;
	}

        
        if (strcmp(inst->mnemonic, "jge") == 0){
                return;
        }

	if (strcmp(inst->mnemonic, "js") == 0){
                return;
        }
	
	if (strcmp(inst->mnemonic, "jns") == 0){
                return;
        }
	
	if (strcmp(inst->mnemonic, "jg") == 0){
                return;
        }

	if (strcmp(inst->mnemonic, "jl") == 0){
                return;
        }

	if (strcmp(inst->mnemonic, "jpe") == 0){
                return;
        }

	if (strcmp(inst->mnemonic, "jcxz") == 0){
		return;
	}

	assert(0);
}


void call_handler(re_list_t *instnode){
	// push eip
	x86_insn_t *inst, *previnst;
	x86_op_t *esp, *dstopd, *eip, *srcopd;
	x86_op_t espmem;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *espmemdef, *useeip, *defesp, *usesrc;
	valset_u tempval = {0}; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	previnst = CAST2_INST(instnode->node)->inst_index - 1 + re_ds.instlist;
	
	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	eip = x86_implicit_operand_1st(inst);
	esp = x86_implicit_operand_2nd(inst);

	INIT_ESPMEM(&espmem, op_expression, op_dword, op_write, esp);
	dstopd = add_new_implicit_operand(inst, &espmem);

	espmemdef = add_new_define(dstopd);

	split_expression_to_use(dstopd);	

	tempval.dword = inst->addr + inst->size;
	assign_def_after_value(espmemdef, tempval);
//	useeip = add_new_use(eip, Opd);
//	assign_use_value(useeip, tempval);

	defesp = add_new_define(esp);
	// directly assign beforevalue here ?
	if (CAST2_DEF(defesp->node)->val_stat & AfterKnown) {
		tempval = CAST2_DEF(defesp->node)->afterval;
		tempval.dword += ADDR_SIZE_IN_BYTE;
		assign_def_before_value(defesp, tempval);
	} else {
		//assert(0);
	}

	srcopd = x86_get_dest_operand(inst);

	switch (srcopd->type) {
		case op_relative_near:
			assert(previnst->addr == inst->addr + inst->size + srcopd->data.relative_near);
			break;
		case op_relative_far:
			//assert(previnst->addr == inst->addr + inst->size + srcopd->data.relative_far);
			break;
		case op_register:
			usesrc = add_new_use(srcopd, Opd);
			break;
		case op_expression:
			usesrc = add_new_use(srcopd, Opd);
			split_expression_to_use(srcopd);
			break;
		default:
			assert(0);
			break;
	}


	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}


void callcc_handler(re_list_t *instnode){
	assert(0);
}


void ret_post_heuristics(re_list_t *retuse, re_list_t *instlist, re_list_t *uselist, re_list_t *deflist){
		val2addr_heuristics(uselist);	
}

void return_handler(re_list_t *instnode){
    	// pop eip
	x86_insn_t *inst, *nextinst;
	x86_op_t *imm, *eip, *esp, *srcopd;
	x86_op_t espmem;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *useret, *useimm, *defeip, *defesp;
	valset_u tempval; 
	// default value for pop() operation
	unsigned disp; 

	disp = ADDR_SIZE_IN_BYTE;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// only two cases for operand combination:
	// explicit operand num = 1 => ret imm
	// explicit operand num = 0 => ret
	if (inst->explicit_count == 1) {
		// oplist : imm, eip, esp
		imm = x86_get_dest_operand(inst); 
		assert(imm->datatype == op_word);
		useimm = add_new_use(imm, Opd);
		switch (imm->datatype) {
		case op_word:
			disp += CAST2_USE(useimm->node)->val.word; 
			break;
		default:
			assert(0);
		}
	} else {
		imm = NULL;
	}

	eip = x86_implicit_operand_1st(inst);
	esp = x86_implicit_operand_2nd(inst);

	// for debugginf use	
	if (inst->explicit_count == 1) {
		print_operand_info(inst->operand_count, imm, eip, esp);
	} else {
		print_operand_info(inst->operand_count, eip, esp);
	}

	// esp = esp + 4;
	defesp = add_new_define(esp);
	// directly assign beforevalue here ?
	if (CAST2_DEF(defesp->node)->val_stat & AfterKnown) {
		tempval = CAST2_DEF(defesp->node)->afterval;
		tempval.dword -= disp;
		assign_def_before_value(defesp, tempval);
	} 

	// eip = [esp];
	defeip = add_new_define(eip);
	if (CAST2_INST(instnode->node)->inst_index > 0) {
		tempval.dword = re_ds.instlist[CAST2_INST(instnode->node)->inst_index-1].addr;
		assign_def_after_value(defeip, tempval);
	}

	INIT_ESPMEM(&espmem, op_expression, op_dword, op_read, esp);
	srcopd = add_new_implicit_operand(inst, &espmem);
	
	useret = add_new_use(srcopd, Opd);
	split_expression_to_use(srcopd);
	
//finish adding use

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	
	ret_post_heuristics(instnode, &re_instlist, &re_uselist, &re_deflist); 

	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void call_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	x86_insn_t *previnst;
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *espmemuse;
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	previnst = CAST2_INST(inst->node)->inst_index - 1 + re_ds.instlist;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert((nuse == 0 && ndef == 2) || (nuse == 1 && ndef == 2));

	// eip = [esp] && eip is always known
/*
	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
	}
	
	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vt =  CAST2_USE(src[0]->node)->val;
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}
*/

	if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown){
		vt = CAST2_DEF(dst[1]->node)->afterval; 
		vt.dword += ADDR_SIZE_IN_BYTE;

		if(CAST2_DEF(dst[1]->node)->val_stat & BeforeKnown)
			assert_val(dst[1], vt, true);
		else{
			assign_def_before_value(dst[1], vt);
			add_to_deflist(dst[1], re_deflist);	
		}
	}

	if(CAST2_DEF(dst[1]->node)->val_stat & BeforeKnown){
		vt = CAST2_DEF(dst[1]->node)->beforeval; 
		vt.dword -= ADDR_SIZE_IN_BYTE;

		if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)
			assert_val(dst[1], vt, false);
		else{
			assign_def_after_value(dst[1], vt);
			add_to_deflist(dst[1], re_deflist);
		}
	}

	if (nuse == 0) return;

	if (ADDRESS_SIZE == 32) {
		vt.dword = previnst->addr;
	} else {
		assert(0);
	}

	if (!CAST2_USE(src[0]->node)->val_known) {
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}
}


void callcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void return_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *espmemuse;
	int nuse, ndef;
	valset_u vs1, vs2, vt;
	unsigned disp = ADDR_SIZE_IN_BYTE;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	if (re_ds.instlist[CAST2_INST(inst->node)->inst_index].explicit_count == 1) {
		assert(nuse == 2 && ndef == 2);
		espmemuse = src[1];
		assert(CAST2_USE(src[0]->node)->operand->datatype == op_word);
		disp += CAST2_USE(src[0]->node)->val.word;
	} else {
		assert(nuse == 1 && ndef == 2);
		espmemuse = src[0];
	}

	// eip = [esp] && eip is always known
	if(CAST2_USE(espmemuse->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(espmemuse, CAST2_DEF(dst[1]->node)->afterval, false);
	}

	if(!CAST2_USE(espmemuse->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[1]->node)->afterval;
		assign_use_value(espmemuse, vt);
		add_to_uselist(espmemuse, re_uselist);
	}

	if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword -= disp;		
		
		if(!(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown)){
			assign_def_before_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, true);
	}

	if(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown){

		vt = CAST2_DEF(dst[0]->node)->beforeval;
		vt.dword += disp; 

		if(!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, false);
	}

}
