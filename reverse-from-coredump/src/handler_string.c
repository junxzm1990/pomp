#include "insthandler.h"


// verify DF = 0 or DF = 1
// return value explaination
// false : DF = 0
// true  : DF = 1
static bool resolve_df(re_list_t *instnode) {
	x86_insn_t *inst;
	int index;

	index = CAST2_INST(instnode->node)->inst_index + 1;

	for (; index<re_ds.instnum; index++) {
		if (strcmp(re_ds.instlist[index].mnemonic, "std") == 0)
			return true;
		if (strcmp(re_ds.instlist[index].mnemonic, "cld") == 0)
			return false;
	}
	return false;
}


void strsca_handler(re_list_t *instnode) {

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *ediop;
	x86_op_t edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	assert(inst->prefix);

	// for debugging use	
	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imp = x86_implicit_operand_1st(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// ecx
	defcount = add_new_define(imp);
	usecount = add_new_use(imp, Opd);

	/*
	// set ecx after value to 0
	memset(&tempval, 0, sizeof(tempval));
	assign_def_after_value(defcount, tempval);
	add_to_deflist(defcount, &re_deflist);
	*/

	INIT_REGOPD(&edi, op_register, op_dword, op_read, src->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

	add_new_define(ediop);
	add_new_use(ediop, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void strcmp_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *ediop, *esiop;
	x86_op_t edi, esi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (strcmp(inst->mnemonic, "scas") == 0) {
		strsca_handler(instnode);
		return;
	}

	assert(inst->prefix);

	// for debugging use	
	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imp = x86_implicit_operand_1st(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// ecx
	defcount = add_new_define(imp);
	usecount = add_new_use(imp, Opd);

	/*
	// set ecx after value to 0
	memset(&tempval, 0, sizeof(tempval));
	assign_def_after_value(defcount, tempval);
	add_to_deflist(defcount, &re_deflist);
	*/

	INIT_REGOPD(&edi, op_register, op_dword, op_read, dst->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

	INIT_REGOPD(&esi, op_register, op_dword, op_read, src->data.expression.base);
	esiop = add_new_implicit_operand(inst, &esi);

	add_new_define(ediop);
	add_new_use(ediop, Opd);

	add_new_define(esiop);
	add_new_use(esiop, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void lods_handler(re_list_t *instnode) {

	x86_insn_t* inst;
	x86_op_t *src, *dst, *esiop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// esi
	INIT_REGOPD(&esi, op_register, op_dword, op_read, src->data.expression.base);
	esiop = add_new_implicit_operand(inst, &esi);

	add_new_define(esiop);
	add_new_use(esiop, Opd);

	// eax, [esi]
	def = add_new_define(dst);
	usesrc = add_new_use(src, Opd);
	split_expression_to_use(src);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void strload_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *esiop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (inst->prefix == 0) {
		lods_handler(instnode);
		return;
	}

	// for debugging use	
	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imp = x86_implicit_operand_1st(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// ecx
	defcount = add_new_define(imp);

	// set ecx after value to 0
	memset(&tempval, 0, sizeof(tempval));
	assign_def_after_value(defcount, tempval);
	add_to_deflist(defcount, &re_deflist);

	// esi = esi +/- 1/2/4 * ecx
	INIT_REGOPD(&esi, op_register, op_dword, op_read, src->data.expression.base);
	esiop = add_new_implicit_operand(inst, &esi);

	add_new_define(esiop);
	add_new_use(esiop, Opd);

	usecount = add_new_use(imp, Opd);

	// eax, [esi]
	def = add_new_define(dst);
	usesrc = add_new_use(src, Opd);
	split_expression_to_use(src);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void movs_handler(re_list_t *instnode) {

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *esiop, *ediop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// edi
	INIT_REGOPD(&edi, op_register, op_dword, op_read, dst->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

	add_new_define(ediop);
	add_new_use(ediop, Opd);

	// esi
	INIT_REGOPD(&esi, op_register, op_dword, op_read, src->data.expression.base);
	esiop = add_new_implicit_operand(inst, &esi);

	add_new_define(esiop);
	add_new_use(esiop, Opd);

	// [edi], [esi]
	def = add_new_define(dst);
	split_expression_to_use(dst);
	usesrc = add_new_use(src, Opd);
	split_expression_to_use(src);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void strmov_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *esiop, *ediop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (inst->prefix == 0) {
		movs_handler(instnode);
		return;
	}

	// for debugging use	
	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imp = x86_implicit_operand_1st(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// ecx
	defcount = add_new_define(imp);
	usecount = add_new_use(imp, Opd);

	/*
	// set ecx after value to 0
	memset(&tempval, 0, sizeof(tempval));
	assign_def_after_value(defcount, tempval);
	add_to_deflist(defcount, &re_deflist);
	*/

	// edi = edi +/- 1/2/4 * ecx
	INIT_REGOPD(&edi, op_register, op_dword, op_read, dst->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

	add_new_define(ediop);
	add_new_use(ediop, Opd);

	// esi = esi + 1/2/4 * ecx
	INIT_REGOPD(&esi, op_register, op_dword, op_read, src->data.expression.base);
	esiop = add_new_implicit_operand(inst, &esi);

	add_new_define(esiop);
	add_new_use(esiop, Opd);

	// [edi] , [esi]
	def = add_new_define(dst);
	split_expression_to_use(dst);
	usesrc = add_new_use(src, Opd);
	split_expression_to_use(src);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void stos_handler(re_list_t *instnode){
	x86_insn_t* inst;
	x86_op_t *src, *dst, *ediop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	// edi
	INIT_REGOPD(&edi, op_register, op_dword, op_read, dst->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

	add_new_define(ediop);
	add_new_use(ediop, Opd);

	// [edi], eax
	def = add_new_define(dst);
	split_expression_to_use(dst);
	usesrc = add_new_use(src, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void strstore_handler(re_list_t *instnode){
	x86_insn_t* inst;
	x86_op_t *src, *dst, *imp, *ediop;
	x86_op_t esi, edi;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc, *defcount, *usecount;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	if (inst->prefix == 0) {
		stos_handler(instnode);
		return;
	}

	// for debugging use	
	print_all_operands(inst);

	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imp = x86_implicit_operand_1st(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	


//mov [edi], eax
//inc edi
//dec ecx

//define and use ecx
	defcount = add_new_define(imp);
	usecount = add_new_use(imp, Opd);

	INIT_REGOPD(&edi, op_register, op_dword, op_read, dst->data.expression.base);
	ediop = add_new_implicit_operand(inst, &edi);

//define and use edi
	add_new_define(ediop);
	add_new_use(ediop, Opd);



//define [edi]
	def = add_new_define(dst);
	split_expression_to_use(dst);

//use eax
	usesrc = add_new_use(src, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void translate_handler(re_list_t *instnode){
	assert(0);
}


void strsca_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vt1, vt;
	bool df;
	size_t size;
	x86_insn_t *instruction;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;	

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 2);

	df = resolve_df(inst);

	size = translate_datatype_to_byte(x86_get_dest_operand(instruction)->datatype);

	// ecx-- | ecx++
	if (CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		assert_val(dst[0], vt, false);
	}

	if (!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword = vt1.dword + 1;

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if (CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	// edi+=1/2/4 | edi-=1/2/4
	if (CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);
		assert_val(dst[1], vt, false);
	}

	if (!CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_DEF(dst[1]->node)->afterval;
		vt.dword = (df)?(vt1.dword + size):(vt1.dword - size);

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}

	if (CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	}
}


void strcmp_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vt1, vt2, vt;
	bool df;
	size_t size;
	x86_insn_t *instruction;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;	

	if (strcmp(instruction->mnemonic, "scas") == 0) {
		strsca_resolver(inst, re_deflist, re_uselist);
		return;
	}

	traverse_inst_operand(inst, src, dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 3 && ndef == 3);

	df = resolve_df(inst);

	size = translate_datatype_to_byte(x86_get_dest_operand(instruction)->datatype);

	// ecx-- | ecx++
	if (CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		assert_val(dst[0], vt, false);
	}

	if (!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword = vt1.dword + 1;

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if (CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	// edi+=1/2/4 | edi-=1/2/4
	if (CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);
		assert_val(dst[1], vt, false);
	}

	if (!CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_DEF(dst[1]->node)->afterval;
		vt.dword = (df)?(vt1.dword + size):(vt1.dword - size);

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}

	if (CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	}	

	// esi+=1/2/4 | esi-=1/2/4
	if (CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[2]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);
		assert_val(dst[2], vt, false);
	}

	if (!CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_DEF(dst[2]->node)->afterval;
		vt.dword = (df)?(vt1.dword + size):(vt1.dword - size);

		assign_use_value(src[2], vt);
		add_to_uselist(src[2], re_uselist);
	}

	if (CAST2_USE(src[2]->node)->val_known 
		&& !(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[2]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);

		assign_def_after_value(dst[2], vt);
		add_to_deflist(dst[2], re_deflist);
	}
}


void lods_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;
	bool df;
	size_t size;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 2);

	df = resolve_df(inst);

	// eax = [esi]
	// esi +/- = 1/2/4(DF, datatype);

	size = translate_datatype_to_byte(CAST2_USE(src[1]->node)->operand->datatype); 	

	// esi = esi +/- 1/2/4
	if(CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_DEF(dst[0]->node)->afterval.dword + size) : 
			(CAST2_DEF(dst[0]->node)->afterval.dword - size);

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	// eax = [esi]
	if(CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(src[1], CAST2_DEF(dst[1]->node)->afterval, false);
	}

	if(CAST2_USE(src[1]->node)->val_known 
			&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[1]->node)->val;

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	} 

	if(!CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[1]->node)->afterval;

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}
}


void strload_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	x86_insn_t *instruction;
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;
	bool df;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;	

	if (instruction->prefix == 0) {
		lods_resolver(inst, re_deflist, re_uselist);
		return;
	}

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 3 && ndef == 3);

	df = resolve_df(inst);	

	// ecx known, ds:[esi] known, eax known
	// how to define def node / use node for continuous memory
	// Just separate continuous memory into several entries by its datatype
	
	// ecx before value is known
	if (CAST2_DEF(dst[0]->node)->val_stat & BeforeKnown) {
		if (df) {
			LOG(stdout, "ALERT: eax <= [esi - (ecx..0)]\n");
			// implement me later
			assert(0);
		} else {
			LOG(stdout, "ALERT: eax <= [esi + (ecx..0)]\n");
			// implement me later
			assert(0);
		}
	}
}


void movs_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;
	bool df;
	size_t size;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 3 && ndef == 3);

	df = resolve_df(inst);

	// [edi] = [esi]
	// edi +/- = 1/2/4(DF, datatype);
	// esi +/- = 1/2/4(DF, datatype);

	size = translate_datatype_to_byte(CAST2_USE(src[2]->node)->operand->datatype); 	

	// edi = edi +/- 1/2/4
	if(CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_DEF(dst[0]->node)->afterval.dword + size) : 
			(CAST2_DEF(dst[0]->node)->afterval.dword - size);

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	// esi = esi +/- 1/2/4
	if(CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[1]->node)->val.dword - size) : 
			(CAST2_USE(src[1]->node)->val.dword + size);
		assert_val(dst[1], vt, false);
	}

	if(CAST2_USE(src[1]->node)->val_known 
			&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[1]->node)->val.dword - size) : 
			(CAST2_USE(src[1]->node)->val.dword + size);

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	} 

	if(!CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_DEF(dst[1]->node)->afterval.dword + size) : 
			(CAST2_DEF(dst[1]->node)->afterval.dword - size);

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}

	// [edi] = [esi]
	if(CAST2_USE(src[2]->node)->val_known 
			&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){
		assert_val(src[2], CAST2_DEF(dst[2]->node)->afterval, false);
	}

	if(CAST2_USE(src[2]->node)->val_known 
			&& !(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[2]->node)->val;

		assign_def_after_value(dst[2], vt);
		add_to_deflist(dst[2], re_deflist);
	} 

	if(!CAST2_USE(src[2]->node)->val_known 
			&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[2]->node)->afterval;

		assign_use_value(src[2], vt);
		add_to_uselist(src[2], re_uselist);
	}
}


void strmov_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	x86_insn_t *instruction;
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vt1, vt2, vt;
	bool df;
	size_t size;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;	

	if (instruction->prefix == 0) {
		movs_resolver(inst, re_deflist, re_uselist);
		return;
	}

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 4 && ndef == 4);

	df = resolve_df(inst);

	size = translate_datatype_to_byte(CAST2_USE(src[1]->node)->operand->datatype);

	// ecx known, ds:[esi] known, es:[edi] known
	// how to define def node / use node for continuous memory
	// Just separate continuous memory into several entries by its datatype
	
	// ecx-- | ecx++
	if (CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		assert_val(dst[0], vt, false);
	}

	if (!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_DEF(dst[0]->node)->afterval;
		vt.dword = vt1.dword + 1;

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	if (CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)) {
		
		vt1 = CAST2_USE(src[0]->node)->val;
		vt.dword = vt1.dword - 1;
		
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	// edi+=1/2/4 | edi-=1/2/4
	if (CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);
		assert_val(dst[1], vt, false);
	}

	if (!CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_DEF(dst[1]->node)->afterval;
		vt.dword = (df)?(vt1.dword + size):(vt1.dword - size);

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}

	if (CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[1]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	}

	// esi+=1/2/4 | esi-=1/2/4
	if (CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[2]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);
		assert_val(dst[2], vt, false);
	}

	if (!CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_DEF(dst[2]->node)->afterval;
		vt.dword = (df)?(vt1.dword + size):(vt1.dword - size);

		assign_use_value(src[2], vt);
		add_to_uselist(src[2], re_uselist);
	}

	if (CAST2_USE(src[2]->node)->val_known 
		&& !(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)) {
		vt1 = CAST2_USE(src[2]->node)->val;
		vt.dword = (df)?(vt1.dword - size):(vt1.dword + size);

		assign_def_after_value(dst[2], vt);
		add_to_deflist(dst[2], re_deflist);
	}

	// [edi] = [esi]
	if (CAST2_USE(src[3]->node)->val_known 
		&& (CAST2_DEF(dst[3]->node)->val_stat & AfterKnown)) {
		vt = CAST2_USE(src[3]->node)->val;
		assert_val(dst[3], vt, false);
	}

	if (!CAST2_USE(src[3]->node)->val_known 
		&& (CAST2_DEF(dst[3]->node)->val_stat & AfterKnown)) {
		vt = CAST2_DEF(dst[3]->node)->afterval;

		assign_use_value(src[3], vt);
		add_to_uselist(src[3], re_uselist);
	}

	if (CAST2_USE(src[3]->node)->val_known 
		&& !(CAST2_DEF(dst[3]->node)->val_stat & AfterKnown)) {
		vt = CAST2_USE(src[3]->node)->val;

		assign_def_after_value(dst[3], vt);
		add_to_deflist(dst[3], re_deflist);
	}
}


void stos_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;
	bool df;
	size_t size;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 2);

	df = resolve_df(inst);

	// [edi] = eax
	// edi +/- = 1/2/4(DF, datatype);

	size = translate_datatype_to_byte(CAST2_USE(src[1]->node)->operand->datatype); 	

	// edi = edi +/- 1/2/4
	if(CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_USE(src[0]->node)->val.dword - size) : 
			(CAST2_USE(src[0]->node)->val.dword + size);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt.dword = (df)? (CAST2_DEF(dst[0]->node)->afterval.dword + size) : 
			(CAST2_DEF(dst[0]->node)->afterval.dword - size);

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

	// [edi] = eax
	if(CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		assert_val(src[1], CAST2_DEF(dst[1]->node)->afterval, false);
	}

	if(CAST2_USE(src[1]->node)->val_known 
			&& !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[1]->node)->val;

		assign_def_after_value(dst[1], vt);
		add_to_deflist(dst[1], re_deflist);
	} 

	if(!CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[1]->node)->afterval;

		assign_use_value(src[1], vt);
		add_to_uselist(src[1], re_uselist);
	}
}

//mov [edi], eax
//inc edi
//dec ecx
// def 0 ecx, def 1 edi, def 2 [edi]
// use 0 ecx, use 1, edi, use 3, eax
void strstore_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	x86_insn_t *instruction;
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vs3, vt1, vt2, vt3;
	bool df;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;	

	if (instruction->prefix == 0) {
		stos_resolver(inst, re_deflist, re_uselist);
		return;
	}

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	
	assert(nuse == 3 && ndef == 3);
		
	df = resolve_df(inst);	
	//df determines incresing edi or decreasing edi	
	if (df) {
		LOG(stdout, "ALERT: [edi - (ecx..0)] <= eax\n");
		assert(0);
		return;
	} 


	//deal with ecx
	if(CAST2_USE(src[0]->node)->val_known){
		//decrease ecx
		vs1 = CAST2_USE(src[0]->node)->val; 
		vs1.dword--;

		if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
			assert_val(dst[0], vs1, false);
		else{
			assign_def_after_value(dst[0], vs1);
			add_to_deflist(dst[0], re_deflist);
		}
	}else{

		if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
			vt1 = CAST2_DEF(dst[0]->node)->afterval; 
			vt1.dword++;
			assign_use_value(src[0], vt1);
			add_to_uselist(src[0], re_uselist);
		}
	}

	//deal with edi
	if(CAST2_USE(src[1]->node)->val_known){
		vs2 = CAST2_USE(src[1]->node)->val; 
		vs2.dword += translate_datatype_to_byte(CAST2_USE(src[2]->node)->operand->datatype);	

		if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)
			assert_val(dst[1], vs2, false);
		else{
			assign_def_after_value(dst[1], vs2);
			add_to_deflist(dst[1], re_deflist);
		}
		
	}else{
		if(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown){
			vt2 = CAST2_DEF(dst[1]->node)->afterval; 
			vt2.dword -= translate_datatype_to_byte(CAST2_USE(src[2]->node)->operand->datatype);
			assign_use_value(src[1], vt2);
			add_to_uselist(src[1], re_uselist);
		}
	}

	// mov [edi], eax
	if(CAST2_USE(src[2]->node)->val_known){
		vs3 = CAST2_USE(src[2]->node)->val; 

		if(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown)
			assert_val(dst[2], vs3, false);
		else{
			assign_def_after_value(dst[2], vs3);
			add_to_deflist(dst[2], re_deflist);
		}
		
	}else{
		if(CAST2_DEF(dst[2]->node)->val_stat & AfterKnown){
			vt3 = CAST2_DEF(dst[2]->node)->afterval; 
			assign_use_value(src[2], vt3);
			add_to_uselist(src[2], re_uselist);
		}
	}
}


void translate_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	assert(0);
}
