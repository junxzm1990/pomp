#include "insthandler.h"

void push_handler(re_list_t *instnode){
	// push ebp =>
	// sub esp, 4
	// mov [esp], ebp
	x86_insn_t* inst;
	x86_op_t *esp, *dstopd, *srcopd;
	x86_op_t espmem;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *defesp, *use;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// this srcopd is first operand of push
	// for example, in 'push eax', srcopd is eax
	srcopd = x86_get_dest_operand(inst);
	esp = x86_implicit_operand_1st(inst);

	// this dstopd is [esp]
	INIT_ESPMEM(&espmem, op_expression, op_dword, op_write, esp);
	dstopd = add_new_implicit_operand(inst, &espmem);
	
	add_new_define(dstopd);
	split_expression_to_use(dstopd);

	defesp = add_new_define(esp);
	// directly assign beforevalue here ?
	if (CAST2_DEF(defesp->node)->val_stat & AfterKnown) {
		tempval = CAST2_DEF(defesp->node)->afterval;
		// push 0x0 => datatype for 0x0 is op_byte
		// change srcopd to dstopd/espmem
		tempval.dword += translate_datatype_to_byte(dstopd->datatype);
		assign_def_before_value(defesp, tempval);
	} 

	switch (srcopd->type) {
		case op_expression:
			use = add_new_use(srcopd, Opd);	
			split_expression_to_use(srcopd);
			break;
		case op_register:
		case op_immediate:
			use = add_new_use(srcopd, Opd);	
			break;
		default: 
			assert(0);	
	}

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}

void pop_handler(re_list_t *instnode){
	// pop ebp =>
	// mov ebp, [esp]
	// add esp, 4
	x86_insn_t* inst;
	x86_op_t *esp, *srcopd, *dstopd;
	x86_op_t espmem;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *defesp;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// this dstopd is first operand of pop
	// for example, in 'pop eax', dstopd is eax
	dstopd = x86_get_dest_operand(inst);
	esp = x86_implicit_operand_1st(inst);

	defesp = add_new_define(esp);
	// directly assign beforevalue here ?
	if (CAST2_DEF(defesp->node)->val_stat & AfterKnown) {
		tempval = CAST2_DEF(defesp->node)->afterval;
		tempval.dword -= translate_datatype_to_byte(dstopd->datatype);
		assign_def_before_value(defesp, tempval);
	} 

	switch (dstopd->type) {
		case op_expression:
			def = add_new_define(dstopd);
			split_expression_to_use(dstopd);
			break;
		case op_register:
			def = add_new_define(dstopd);
			break;
	}

	// this srcopd is [esp]
	INIT_ESPMEM(&espmem, op_expression, op_dword, op_read, esp);
	srcopd = add_new_implicit_operand(inst, &espmem);

	add_new_use(srcopd, Opd);
	split_expression_to_use(srcopd);
	
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}

void pushregs_handler(re_list_t *inst){
	assert(0);
#if 0
    x86_op_t *dst = x86_get_dest_operand(inst);
    x86_op_t *src = x86_get_src_operand(inst);
    unsigned long index = appinst - instlist;
    print_operand_info(inst->operand_count, dst, src);
    // add contraint

    /*
    LOG(stdout, "DEBUG: It is irreversible\n");
    appinst->reversible = direct_irreversible;
    add_opd_in_deflist(index, &urmdefhead, dst);
    appdefheadlist_t *temp = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
    */
    appdefheadlist_t *defsrc = NULL;
    int valueafter = 0;
    switch (get_operand_combine(inst)) {
    case dest_register_src_expression:
        break;
    case src_immediate:
        break;
    default:
        // need code to handle those constraints
        assert(0);
        break;
    }

    print_defheadlist(&urmdefhead);
    print_info_of_one_instruction(appinst);
#endif
}

void popregs_handler(re_list_t *inst){
	assert(0);
#if 0
    x86_insn_t *inst = &appinst->inst;
    x86_op_t *dst = x86_get_dest_operand(inst);
    x86_op_t *src = x86_get_src_operand(inst);
    unsigned long index = appinst - instlist;
    print_operand_info(inst->operand_count, dst, src);
    // add contraint

    /*
    LOG(stdout, "DEBUG: It is irreversible\n");
    appinst->reversible = direct_irreversible;
    add_opd_in_deflist(index, &urmdefhead, dst);
    appdefheadlist_t *temp = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
    */
    appdefheadlist_t *defsrc = NULL;
    int valueafter = 0;
    switch (get_operand_combine(inst)) {
    case dest_register_src_expression:
        break;
    case src_immediate:
        break;
    default:
        // need code to handle those constraints
        assert(0);
        break;
    }

    print_defheadlist(&urmdefhead);
    print_info_of_one_instruction(appinst);
#endif
}

void pushflags_handler(re_list_t *inst){
	assert(0);
#if 0
    x86_op_t *dst = x86_get_dest_operand(inst);
    x86_op_t *src = x86_get_src_operand(inst);
    unsigned long index = appinst - instlist;
    print_operand_info(inst->operand_count, dst, src);
    // add contraint

    /*
    LOG(stdout, "DEBUG: It is irreversible\n");
    appinst->reversible = direct_irreversible;
    add_opd_in_deflist(index, &urmdefhead, dst);
    appdefheadlist_t *temp = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
    */
    appdefheadlist_t *defsrc = NULL;
    int valueafter = 0;
    switch (get_operand_combine(inst)) {
    case dest_register_src_expression:
        break;
    case src_immediate:
        break;
    default:
        // need code to handle those constraints
        assert(0);
        break;
    }

    print_defheadlist(&urmdefhead);
    print_info_of_one_instruction(appinst);
#endif
}

void popflags_handler(re_list_t *inst){
	assert(0);
#if 0
    x86_op_t *dst = x86_get_dest_operand(inst);
    x86_op_t *src = x86_get_src_operand(inst);
    unsigned long index = appinst - instlist;
    print_operand_info(inst->operand_count, dst, src);
    // add contraint

    /*
    LOG(stdout, "DEBUG: It is irreversible\n");
    appinst->reversible = direct_irreversible;
    add_opd_in_deflist(index, &urmdefhead, dst);
    appdefheadlist_t *temp = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
    */
    appdefheadlist_t *defsrc = NULL;
    int valueafter = 0;
    switch (get_operand_combine(inst)) {
    case dest_register_src_expression:
        break;
    case src_immediate:
        break;
    default:
        // need code to handle those constraints
        assert(0);
        break;
    }

    print_defheadlist(&urmdefhead);
    print_info_of_one_instruction(appinst);
#endif
}

void enter_handler(re_list_t *inst){
	assert(0);
#if 0
    x86_op_t *dst = x86_get_dest_operand(inst);
    x86_op_t *src = x86_get_src_operand(inst);
    unsigned long index = appinst - instlist;
    print_operand_info(inst->operand_count, dst, src);
    // add contraint

    /*
    LOG(stdout, "DEBUG: It is irreversible\n");
    appinst->reversible = direct_irreversible;
    add_opd_in_deflist(index, &urmdefhead, dst);
    appdefheadlist_t *temp = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
    */
    appdefheadlist_t *defsrc = NULL;
    int valueafter = 0;
    switch (get_operand_combine(inst)) {
    case dest_register_src_expression:
        break;
    case src_immediate:
        break;
    default:
        // need code to handle those constraints
        assert(0);
        break;
    }

    print_defheadlist(&urmdefhead);
    print_info_of_one_instruction(appinst);
#endif
}

// no explicit operand
// two implicit operands
void leave_handler(re_list_t *instnode){
	// esp = ebp
	// ebp = [esp]
	// esp = esp + 4
	x86_insn_t *inst;
	x86_op_t *src, *dst;
	x86_op_t *esp, *ebp, *srcopd;
	x86_op_t espmem;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *defebp, *defesp, *useebp;
	valset_u tempval; 
	unsigned disp;

	disp = ADDR_SIZE_IN_BYTE;

	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	esp = x86_implicit_operand_1st(inst);
	ebp = x86_implicit_operand_2nd(inst);

	// for debugginf use	
	print_operand_info(inst->operand_count, esp, ebp);

	// esp = esp + 4;
	defesp = add_new_define(esp);
	// directly assign beforevalue here ?
	if (CAST2_DEF(defesp->node)->val_stat & AfterKnown) {
		tempval = CAST2_DEF(defesp->node)->afterval;
		tempval.dword -= disp; 
		assign_def_before_value(defesp, tempval);
	}

	// ebp = [esp]
	defebp = add_new_define(ebp);

	INIT_ESPMEM(&espmem, op_expression, op_dword, op_read, esp);
	srcopd = add_new_implicit_operand(inst, &espmem);

	add_new_use(srcopd, Opd);
	split_expression_to_use(srcopd);

	// esp = ebp;
	defesp = add_new_define(esp);
	useebp = add_new_use(ebp, Opd);

	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}


void push_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *espmemuse;
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 1 && ndef == 2);

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

	      	assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
	}

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[0]->node)->afterval;
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vt = CAST2_USE(src[0]->node)->val;

		sign_extend_valset(&vt, CAST2_USE(src[0]->node)->operand->datatype);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

//added by JX
	if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown){
		vt = CAST2_DEF(dst[1]->node)->afterval;
		vt.dword += ADDR_SIZE_IN_BYTE;		
		
		if(!(CAST2_DEF(dst[1]->node)->val_stat & BeforeKnown)){
			assign_def_before_value(dst[1], vt);
			add_to_deflist(dst[1], re_deflist);
		}else
			assert_val(dst[1], vt, true);
	}

//added by JX
	if(CAST2_DEF(dst[1]->node)->val_stat & BeforeKnown){

		vt = CAST2_DEF(dst[1]->node)->beforeval;
		vt.dword -= ADDR_SIZE_IN_BYTE; 

		if(!(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
			assign_def_after_value(dst[1], vt);
			add_to_deflist(dst[1], re_deflist);
		}else
			assert_val(dst[1], vt, false);
	}
}


void pop_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	re_list_t *espmemuse;
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 1 && ndef == 2);

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[1]->node)->afterval, false);
	}

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[1]->node)->afterval;
		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt = CAST2_USE(src[0]->node)->val;
		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	}

	if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword -= ADDR_SIZE_IN_BYTE;		
		
		if(!(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown)){
			assign_def_before_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, true);
	}

	if(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown){

		vt = CAST2_DEF(dst[0]->node)->beforeval;
		vt.dword += ADDR_SIZE_IN_BYTE; 

		if(!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, false);
	}
}


void pushregs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void popregs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void pushflags_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void popflags_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void enter_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}


void leave_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	
	assert(nuse == 2 && ndef == 3);
	// ebp = [esp]
	if(CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(src[0], CAST2_DEF(dst[1]->node)->afterval, false);
	}

	// ebp : UnKnown, [esp] : known
	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[0]->node)->val;
		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	}

	// ebp : Known, [esp] : Unknown
	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[1]->node)->afterval;
		assign_use_value(src[0], vt);
		//list_add(&src[0]->uselist, &re_uselist->uselist);	
		add_to_uselist(src[0], re_uselist);
	}

	// esp = ebp;
	if(CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){
		assert_val(src[1], CAST2_DEF(dst[2]->node)->afterval, false);
	}

	// esp : Unknown, ebp : Known
	if(CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[1]->node)->val;
		assign_def_after_value(dst[2], vt);
		add_to_deflist(dst[2], re_deflist);
	}

	// esp : Known, ebp : UnKnown
	if(!CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){

		vt = CAST2_DEF(dst[2]->node)->afterval;
		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}

	// esp(after) = esp(before) + ADDR_SIZE_IN_BYTE
	if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
		vt = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword -= ADDR_SIZE_IN_BYTE;		
	
		if(!(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown)){
			assign_def_before_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, true);
	}

	if(CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown){

		vt = CAST2_DEF(dst[0]->node)->beforeval;
		vt.dword += ADDR_SIZE_IN_BYTE; 

		if(!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}else
			assert_val(dst[0], vt, false);
	}

}
