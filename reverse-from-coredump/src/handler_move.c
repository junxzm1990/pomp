#include "insthandler.h"

#define REVERSE_UINT(num) \
	((num>>24) & 0x000000ff) | \
	((num<< 8) & 0x00ff0000) | \
	((num>> 8) & 0x0000ff00) | \
	((num<<24) & 0xff000000)


void mov_post_heuristics(re_list_t *instnode, re_list_t *instlist, re_list_t *uselist, re_list_t *deflist){

	val2addr_heuristics(uselist);	
}


void mov_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def,*usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	
	// if it is lea instruction, forward to lea handler
	if (strcmp(inst->mnemonic, "lea") == 0) {
		lea_handler(instnode);
		return;
	}

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	convert_offset_to_exp(src);
	convert_offset_to_exp(dst);	

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
			usesrc = add_new_use(src, Opd);
			break;
		case dest_register_src_expression:

			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);	
			
			break;

		case dest_expression_src_register:
			def = add_new_define(dst);	
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);		
			break;

		case dest_expression_src_imm:
			def = add_new_define(dst);	
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);		
			break;
		case dest_register_src_imm:
			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			break;
	
		case dest_offset_src_register:
			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);

//adding post heuristics here
//	mov_post_heuristics(instnode, &re_instlist, &re_uselist, &re_deflist);

//	re_resolve(&re_deflist, &re_uselist, &re_instlist);
//print the final result of the analysis
}


void lea_handler(re_list_t *instnode){
	
	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def,*usesrc;
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
		case dest_register_src_expression:
			def = add_new_define(dst);
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);		
			break;

		default:
			assert(0);
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}


void movcc_handler(re_list_t *instnode){
	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def,*usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	dst = x86_get_dest_operand(inst);

//	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	switch (dst->type) {
		case op_byte:
			def = add_new_define(dst);
			break;
		case op_expression:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			break;
		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}


void bswap_handler(re_list_t *instnode) {

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *defdst, *defsrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	dst = x86_get_dest_operand(inst);

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	assert(dst->type == op_register);

	add_new_define(dst);
	add_new_use(dst, Opd);

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	
	print_info_of_current_inst(instnode);
}


void xchg_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *defdst, *defsrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "bswap") == 0) {
		bswap_handler(instnode);
		return;
	}
	
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	convert_offset_to_exp(src);
	convert_offset_to_exp(dst);	

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	// through resdeflist, we could link all the entry 
	// needed to  be resolved together
	switch(get_operand_combine(inst)){
		case dest_register_src_register:
			defdst = add_new_define(dst);
			defsrc = add_new_define(src);
			add_new_use(dst, Opd);
			add_new_use(src, Opd);
			break;
		case dest_expression_src_register:
			defdst = add_new_define(dst);
			split_expression_to_use(dst);
			defsrc = add_new_define(src);
			add_new_use(dst, Opd);
			split_expression_to_use(dst);
			add_new_use(src, Opd);
			break;
		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	
	print_info_of_current_inst(instnode);
}


void xchgcc_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *eax, *dstopd, *srcopd;
	re_list_t re_deflist, re_uselist, re_instlist;  	
        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	dstopd = x86_get_dest_operand(inst);
	srcopd = x86_get_src_operand(inst);
	eax = x86_implicit_operand_1st(inst);

	print_operand_info(inst->operand_count, dstopd, srcopd, eax);	

	switch(get_operand_combine(inst)){
//the implicit operand of eax may be used in the destination
		case dest_register_src_register:
			add_new_define(eax);
			add_new_define(dstopd);
			add_new_use(dstopd, Opd);
			add_new_use(eax, Opd);
			add_new_use(srcopd, Opd);
			break;

		case dest_expression_src_register:
			add_new_define(eax);
			add_new_define(dstopd);
			split_expression_to_use(dstopd);
			add_new_use(dstopd, Opd);
			split_expression_to_use(dstopd);
			add_new_use(eax, Opd);
			add_new_use(srcopd, Opd); 
			break;

		default: 
			assert(0);

	}
	
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}

static bool process_other_mov_inst(re_list_t *instnode, re_list_t *re_deflist, re_list_t *re_uselist) {

	x86_insn_t *inst;
	
	inst= re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "mov") == 0) {
		return true;
	}

	if (strcmp(inst->mnemonic, "lea") == 0) {
		lea_resolver(instnode, re_deflist, re_uselist);
		return false;
	}

	if (strcmp(inst->mnemonic, "movdqu") == 0) {
		return true;
	}

	if (strcmp(inst->mnemonic, "movdqa") == 0) {
		return true;
	}

	if (strcmp(inst->mnemonic, "movaps") == 0) {
		return true;
	}

	if (strcmp(inst->mnemonic, "movzx") == 0) {
		movzx_resolver(instnode, re_deflist, re_uselist);
		return false;
	}

	if (strcmp(inst->mnemonic, "movsx") == 0) {
		movsx_resolver(instnode, re_deflist, re_uselist);
		return false;
	}

	if (strcmp(inst->mnemonic, "movlpd") == 0) {
		movlpd_resolver(instnode, re_deflist, re_uselist);
		return false;
	}


	assert(0);
}

void mov_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){

	if (!process_other_mov_inst(inst, deflist, uselist)) {
		return;
	}

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);
	//assert(CAST2_DEF(dst[0]->node)->operand->datatype == CAST2_USE(src[0]->node)->operand->datatype);

	//add pre heuristics

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[0]->node)->val;

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		assign_use_value(src[0], vt);

		add_to_uselist(src[0], uselist);
	}

	//adding post heuristics 
}

void movzx_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);
	assert(CAST2_DEF(dst[0]->node)->operand->datatype > CAST2_USE(src[0]->node)->operand->datatype);

	//add pre heuristics

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[0]->node)->val;
		clean_valset(&vt, CAST2_USE(src[0]->node)->operand->datatype, false);
		
		zero_valset(&(CAST2_DEF(dst[0]->node)->afterval));

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	}

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], uselist);
	}

	//adding post heuristics 

}

void movsx_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);
	assert(CAST2_DEF(dst[0]->node)->operand->datatype > CAST2_USE(src[0]->node)->operand->datatype);

	//add pre heuristics

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vt = CAST2_USE(src[0]->node)->val;
		sign_extend_valset(&vt, CAST2_USE(src[0]->node)->operand->datatype);
		
		one_valset(&(CAST2_DEF(dst[0]->node)->afterval));

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	}

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], uselist);
	}

	//adding post heuristics 

}

// verify address of src operand in lea is zero or not
static bool verify_zero_address(re_list_t *exp) {
	re_list_t *index, *base, *entry; 
	x86_op_t *opd;
	unsigned baseaddr, indexaddr, address;

	opd = CAST2_USE(exp->node)->operand;

	get_element_of_exp(exp, &index, &base);

	switch (exp_addr_status(base, index)) {
		case KBaseKIndex:
			if (base){
				baseaddr = CAST2_USE(base->node)->val.dword;
			}

			if (index) {
				indexaddr = CAST2_USE(index->node)->val.dword;
			}
		
			address = baseaddr + indexaddr * opd->data.expression.scale + 
		    		(int)(opd->data.expression.disp);
			return (address == 0);
			break;
		default:
			return false;
	}

}

void lea_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt;
	bool zeroaddr = false;
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);

	zeroaddr = verify_zero_address(src[0]);

	if((CAST2_USE(src[0]->node)->address || zeroaddr)
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = CAST2_USE(src[0]->node)->address;
		assert_val(dst[0], vt, false);
	}

	if((CAST2_USE(src[0]->node)->address || zeroaddr)
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		if (CAST2_DEF(dst[0]->node)->operand->datatype == op_dword) {
			vt.dword = CAST2_USE(src[0]->node)->address;
			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		} else {
			assert(0);
		}
	} 

	if(!(CAST2_USE(src[0]->node)->address || zeroaddr)
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[0]->node)->afterval;
		CAST2_USE(src[0]->node)->address = vt.dword;
		// infer base/index register value from the address

		re_list_t *index, *base;
		x86_op_t *opd = CAST2_USE(src[0]->node)->operand;
		int temp;

		get_element_of_exp(src[0], &index, &base);
		switch (exp_addr_status(base, index)) {
			case UBase:
				vt.dword = CAST2_USE(src[0]->node)->address - 
					   opd->data.expression.disp;
				assign_use_value(base, vt);
				add_to_uselist(base, re_uselist);
				break;
			case UBaseUIndex:
				if (opd->data.expression.index.id == opd->data.expression.base.id) {
					vt.dword = CAST2_USE(src[0]->node)->address - 
						opd->data.expression.disp;

					vt.dword /= (1 + opd->data.expression.scale);
					assign_use_value(base, vt);
					add_to_uselist(base, re_uselist);
				}
				break;
			case KBaseUIndex:
				temp = CAST2_USE(src[0]->node)->address - CAST2_USE(base->node)->val.dword - opd->data.expression.disp;
				vt.dword = temp / (opd->data.expression.scale);
				assign_use_value(index, vt);
				add_to_uselist(index, re_uselist);
				break;
			case UBaseKIndex:
				vt.dword = CAST2_USE(src[0]->node)->address - 
					CAST2_USE(index->node)->val.dword * opd->data.expression.scale - 
					opd->data.expression.disp;
				assign_use_value(base, vt);
				add_to_uselist(base, re_uselist);
				break;
			default:
				assert(0);
				return; 
		} 
	}
}

void movcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	LOG(stdout, "ALERT: We need to take care of eflags register here\n");
}


static bool process_other_xchg_inst(re_list_t *instnode, re_list_t *re_deflist, re_list_t *re_uselist) {
	x86_insn_t *inst;
	
	inst= re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "xchg") == 0) {
		return true;
	}

	if (strcmp(inst->mnemonic, "bswap") == 0) {
		bswap_resolver(instnode, re_deflist, re_uselist);
		return false;
	}

	assert("Other xchg inst" && 0);

}


void bswap_resolver(re_list_t *inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef == 1);

	assert(CAST2_DEF(dst[0]->node)->operand->datatype == op_dword);

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = REVERSE_UINT(CAST2_USE(src[0]->node)->val.dword);
		assert_val(dst[0], vt, false);
	}

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = REVERSE_UINT(CAST2_DEF(dst[0]->node)->afterval.dword);

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = REVERSE_UINT(CAST2_USE(src[0]->node)->val.dword);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}
}

void xchg_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	if (!process_other_xchg_inst(inst, re_deflist, re_uselist)) {
		return;
	}

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 2 && ndef == 2);

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[1]->node)->afterval, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[0]->node)->val;

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[1]->node)->afterval;

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if(CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(src[1], CAST2_DEF(dst[0]->node)->afterval, false);
	}

	if(CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[1]->node)->val;

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[0]->node)->afterval;

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}
}


void xchgcc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  *veax, *vdst, *vsrc, *vt;
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 3 && ndef == 2);
	
	vdst = &CAST2_USE(src[0]->node)->val;	
	veax = &CAST2_USE(src[1]->node)->val; 
	vsrc = &CAST2_USE(src[2]->node)->val; 
				
	switch(CAST2_USE(src[1]->node)->operand->datatype){

		case op_byte:

			//the values for comparison are known
			
			if(CAST2_USE(src[0]->node)->val_known && CAST2_USE(src[1]->node)->val_known){
				// AL with r/m8
				if(vdst->byte == veax->byte){

					//r8
					if(!CAST2_USE(src[2]->node)->val_known){

						//r/m8
						if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown){
							vt = &CAST2_DEF(dst[1]->node)->afterval; 
							assign_use_value(src[2], *vt);
							add_to_uselist(src[2], re_uselist);
						}

						return;
					}


					vt = vsrc; 

					if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown){
						assert_val(dst[1], *vt, false);
					}else{

						assign_def_after_value(dst[1], *vt);
						add_to_deflist(dst[1], re_deflist);	
					}

					return;
				}

				
				if(CAST2_USE(src[0]->node)->val_known){

					vt = &CAST2_USE(src[0]->node)->val;

					if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
						assert_val(dst[0], *vt, false);
					}else{

						assign_def_after_value(dst[0], *vt);
						add_to_deflist(dst[0], re_deflist);
					}
					return; 
				}
				
				if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){

					vt = &CAST2_DEF(dst[0]->node)->afterval;
					assign_use_value(src[0], *vt);
					add_to_uselist(src[0], re_uselist);
				}
				return; 
			}

			break;

		default: 
			assert(0);
			
	}	

}





