#include "insthandler.h"
#include "solver.h"

// left rotate
static unsigned rol_int(unsigned num, int bits){
      return ((num << bits) | (num >> (sizeof(int)*8-bits)));
} 

//right rotate
static unsigned ror_int(unsigned num, int bits){
      return ((num >> bits) | (num << (sizeof(int)*8-bits)));
}


void add_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

		case dest_expression_src_imm:
			def = add_new_define(dst);	
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);					
			break;

		case dest_expression_src_register:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_imm:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void sub_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

		case dest_expression_src_register:
			def = add_new_define(dst);	
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
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
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void mul_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imm, *edx;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc, *useimm, *defedx;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	switch (inst->explicit_count) {
		case 2:
			dst = x86_get_dest_operand(inst);
			src = x86_get_src_operand(inst);

			// for debugging use	
			print_all_operands(inst);

			// two cases for two explicit operands
			// 1. imul ebx
			// (inst->explicit_count != inst->operand_count)

			if (inst->explicit_count != inst->operand_count) {
				edx = x86_implicit_operand_1st(inst);

				defedx = add_new_define(edx);
				def = add_new_define(dst);
				usedst = add_new_use(dst, Opd);
				usesrc = add_new_use(src, Opd);
			} else {
			// 2. imul ebx, ecx
			// (inst->explicit_count == inst->operand_count)

				switch (get_operand_combine(inst)) {

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
			}
			
			break;
		case 3:
			dst = x86_get_dest_operand(inst);
			src = x86_get_src_operand(inst);
			imm = x86_get_imm_operand(inst);

			// for debugging use
			print_all_operands(inst);

			switch (get_operand_combine(inst)) {

				case dest_register_src_register:
					def = add_new_define(dst);
					usesrc = add_new_use(src, Opd);
					useimm = add_new_use(imm, Opd);
					break;

				case dest_register_src_expression:
					def = add_new_define(dst);
					usesrc = add_new_use(src, Opd);
					split_expression_to_use(src);
					useimm = add_new_use(imm, Opd);
					break;

				default:
					assert(0);
					break;
			}

			break;
		default:
			assert(0);
			break;
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void div_handler(re_list_t * instnode){
	
	x86_insn_t* inst;
	// eax/al, divisor, edx/dl
	x86_op_t *dst, *src, *imp;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	switch (src->datatype) {
		case op_byte:
			assert((inst->operand_count==4) && (inst->explicit_count==2));
			imp = x86_implicit_operand_2nd(inst);
			break;
		case op_dword:
			imp = x86_implicit_operand_1st(inst); 
			break;
		default:
			assert("Verify implicit operand here" && 0);
			break;
	}

	// for debugginf use	
	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

	add_new_define(dst);
	add_new_define(imp);
	switch (src->type) {

		case op_expression:
			usesrc = add_new_use(src, Opd);
			split_expression_to_use(src);
			break;

		case op_register:
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);
			break;
	}
	add_new_use(dst, Opd);
	add_new_use(imp, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void inc_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void dec_handler(re_list_t * instnode){
	
	x86_insn_t* inst;
	x86_op_t *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void shl_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	// for debugging use	
	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	// through resdeflist, we could link all the entry 
	// needed to  be resolved together
	switch(get_operand_combine(inst)){

		case dest_expression_src_imm:
			def = add_new_define(dst);	
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_imm:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void shr_handler(re_list_t * instnode){
	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	//	for debugginf use
	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);

	// through resdeflist, we could link all the entry
	// needed to  be resolved together
	switch(get_operand_combine(inst)){

		case dest_expression_src_imm:
			def = add_new_define(dst);
			split_expression_to_use(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_imm:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		case dest_register_src_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);
			break;

		default:
			assert(0);

	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void rol_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void ror_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	// for debugging use	
	print_all_operands(inst);

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

		default:
			assert(0);
	}

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}


void add_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);

	// check here
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs1.byte + vs2.byte;
				break;	
			case op_word:	
				vt.word = vs1.word + vs2.word;
				break;	
			case op_dword:
				vt.dword = vs1.dword + vs2.dword;
				break;	
			default:
				assert("Fuck you" && 0);
		}
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs1.byte + vs2.byte;
				break;	
			case op_word:	
				vt.word = vs1.word + vs2.word;

				break;	
			case op_dword:
				vt.dword = vs1.dword + vs2.dword;

				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(CAST2_USE(src[0]->node)->val_known 
		&& !CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte - vs1.byte;

				break;	
			case op_word:	
				vt.word = vs2.word - vs1.word;

				break;	
			case op_dword:
				vt.dword = vs2.dword - vs1.dword;

				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_use_value(src[1], vt);	
		add_to_uselist(src[1], re_uselist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[1]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte - vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word - vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword - vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	} 

#ifdef WITH_SOLVER
	add_solver(inst, src, dst, nuse, ndef);
#endif

}


void sub_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);

	// check here
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs1.byte - vs2.byte;
				break;	
			case op_word:	
				vt.word = vs1.word - vs2.word;
				break;	
			case op_dword:
				vt.dword = vs1.dword - vs2.dword;
				break;	
			default:
				assert("Fuck you" && 0);
		}
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs1.byte - vs2.byte;
				break;	
			case op_word:	
				vt.word = vs1.word - vs2.word;

				break;	
			case op_dword:
				vt.dword = vs1.dword - vs2.dword;

				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(CAST2_USE(src[0]->node)->val_known 
		&& !CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs1.byte - vs2.byte;

				break;	
			case op_word:	
				vt.word = vs1.word - vs2.word;

				break;	
			case op_dword:
				vt.dword = vs1.dword - vs2.dword;

				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_use_value(src[1], vt);	
		add_to_uselist(src[1], re_uselist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[1]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		switch(CAST2_USE(src[0]->node)->operand->datatype){
			case op_byte: 
				vt.byte = vs2.byte + vs1.byte;
				break;

			case op_word:	
				vt.word = vs2.word + vs1.word;
				break;

			case op_dword:
				vt.dword = vs2.dword + vs1.dword;
				break;

			default:
				assert("Fuck you wrong size" && 0);
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}

#ifdef WITH_SOLVER
//	sub_solver(src, dst, nuse, ndef);
#endif	
 
}

void mul_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vt1, vt2, vt3, vt;
	x86_insn_t *instruction;

	instruction = re_ds.instlist + CAST2_INST(inst->node)->inst_index;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	if (instruction->explicit_count != instruction->operand_count) {
		// imul eax
		assert(nuse == 2 && ndef == 2);

		// edx : eax = eax * src
		// dst0  dst1  src0  src1
		// check here
		if(CAST2_USE(src[0]->node)->val_known 
			&& CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {

			vt1 = CAST2_USE(src[0]->node)->val;

			vt3 = CAST2_DEF(dst[0]->node)->afterval;
			vt2 = CAST2_DEF(dst[1]->node)->afterval;
			
			switch (CAST2_DEF(dst[1]->node)->operand->datatype) {
				case op_byte:
					vt.byte = ((vt3.byte << BYTE_SIZE) + vt2.byte) / vt1.byte;
					break;
				case op_word:
					vt.word = ((vt3.word << WORD_SIZE) + vt2.word) / vt1.word;
					break;
				case op_dword:
					vt.dword = ((((long long)vt3.dword) << DWORD_SIZE) + vt2.dword) / vt1.dword;
					break;
			}
			assert_val(src[1], vt, false);
		}

		if(!CAST2_USE(src[0]->node)->val_known 
			&& CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {

			vt1 = CAST2_USE(src[1]->node)->val;

			vt3 = CAST2_DEF(dst[0]->node)->afterval;
			vt2 = CAST2_DEF(dst[1]->node)->afterval;

			switch (CAST2_DEF(dst[1]->node)->operand->datatype) {
				case op_byte:
					vt.byte = ((vt3.byte << BYTE_SIZE) + vt2.byte) / vt1.byte;
					break;
				case op_word:
					vt.word = ((vt3.word << WORD_SIZE) + vt2.word) / vt1.word;
					break;
				case op_dword:
					vt.dword = ((((long long)vt3.dword) << DWORD_SIZE) + vt2.dword) / vt1.dword;
					break;
			}

			assign_use_value(src[0], vt);

			add_to_uselist(src[0], re_uselist);
		}

		if(CAST2_USE(src[0]->node)->val_known 
			&& !CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
			&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)) {

			vt1 = CAST2_USE(src[0]->node)->val;

			vt3 = CAST2_DEF(dst[0]->node)->afterval;
			vt2 = CAST2_DEF(dst[1]->node)->afterval;

			switch (CAST2_DEF(dst[1]->node)->operand->datatype) {
				case op_byte:
					vt.byte = ((vt3.byte << BYTE_SIZE) + vt2.byte) / vt1.byte;
					break;
				case op_word:
					vt.word = ((vt3.word << WORD_SIZE) + vt2.word) / vt1.word;
					break;
				case op_dword:
					vt.dword = ((((long long)vt3.dword) << DWORD_SIZE) + vt2.dword) / vt1.dword;
					break;
			}

			assign_use_value(src[1], vt);

			add_to_uselist(src[1], re_uselist);
		}

		if(CAST2_USE(src[0]->node)->val_known 
			&& CAST2_USE(src[1]->node)->val_known 
			&& (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) 
			||  !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown))) {

			vt = CAST2_USE(src[0]->node)->val;
			vt1 = CAST2_USE(src[1]->node)->val;

			switch (CAST2_DEF(dst[1]->node)->operand->datatype) {
				case op_byte:
					vt2.byte = (vt1.byte * vt.byte) % (1 << BYTE_SIZE);
					vt3.byte = (vt1.byte * vt.byte) / (1 << BYTE_SIZE);
					break;
				case op_word:
					vt2.word = (vt1.word * vt.word) % (1 << WORD_SIZE);
					vt3.word = (vt1.word * vt.word) / (1 << WORD_SIZE);
					break;
				case op_dword:
					vt2.dword = (((long long)vt1.dword) * vt.dword) % (((long long)1) << DWORD_SIZE);
					vt3.dword = (((long long)vt1.dword) * vt.dword) / (((long long)1) << DWORD_SIZE);
					break;
			}
			assign_def_after_value(dst[0], vt3);
			assign_def_after_value(dst[1], vt2);

			print_node(dst[0]);
			print_node(dst[1]);

			add_to_deflist(dst[0], re_deflist);
			add_to_deflist(dst[1], re_deflist);
		}
	} else {
		// imul eax, ebx
		// imul eax, ebx, imm

		assert(nuse == 2 && ndef == 1);

		// check here
		if(CAST2_USE(src[0]->node)->val_known 
				&& CAST2_USE(src[1]->node)->val_known 
				&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

			vt1 = CAST2_USE(src[0]->node)->val;
			vt2 = CAST2_USE(src[1]->node)->val;

			switch(CAST2_USE(src[0]->node)->operand->datatype){
				case op_word:	
					vt.word = vt1.word * vt2.word;
					break;	
				case op_dword:
					vt.dword = vt1.dword * vt2.dword;
					break;	
				default:
					assert("Other datatype" && 0);
			}
			assert_val(dst[0], vt, false);
		}

		if(CAST2_USE(src[0]->node)->val_known 
				&& CAST2_USE(src[1]->node)->val_known 
				&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

			vt1 = CAST2_USE(src[0]->node)->val;
			vt2 = CAST2_USE(src[1]->node)->val;

			switch(CAST2_USE(src[0]->node)->operand->datatype){
				case op_word:	
					vt.word = vt1.word * vt2.word;
					break;	
				case op_dword:
					vt.dword = vt1.dword * vt2.dword;
					break;	
				default:
					assert("Other datatype" && 0);
			}

			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		} 

		if(CAST2_USE(src[0]->node)->val_known 
				&& !CAST2_USE(src[1]->node)->val_known 
				&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

			vt1 = CAST2_USE(src[0]->node)->val;
			vt2 = CAST2_DEF(dst[0]->node)->afterval;

			switch(CAST2_USE(src[0]->node)->operand->datatype){
				case op_word:	
					vt.word = vt2.word / vt1.word;
					break;	
				case op_dword:
					vt.dword = vt2.dword / vt1.dword;
					break;	
				default:
					assert("Other datatype" && 0);
			}

			assign_use_value(src[1], vt);	
			add_to_uselist(src[1], re_uselist);
		} 

		if(!CAST2_USE(src[0]->node)->val_known 
				&& CAST2_USE(src[1]->node)->val_known 
				&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

			vt1 = CAST2_USE(src[1]->node)->val;
			vt2 = CAST2_DEF(dst[0]->node)->afterval;

			switch(CAST2_USE(src[0]->node)->operand->datatype){
				case op_word:	
					vt.word = vt2.word / vt1.word;
					break;
				case op_dword:
					vt.dword = vt2.dword / vt1.dword;
					break;
				default:
					assert("Other datatype" && 0);
			}

			assign_use_value(src[0], vt);
			add_to_uselist(src[0], re_uselist);
		} 

	}
}


void div_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vt1={0}, vt2={0}, vt={0};
	valset_u vt3={0}, vt4={0}, vtdiv={0};

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 3 && ndef == 2);

	assert(CAST2_DEF(dst[0]->node)->operand->datatype == 
		CAST2_DEF(dst[1]->node)->operand->datatype);

	assert(CAST2_DEF(dst[0]->node)->operand->datatype == 
		CAST2_USE(src[0]->node)->operand->datatype);
	// Dividend  /  Divisor = Quotient...Remainder
	// EDX : EAX    Divisor	  EAX	  ...EDX
	//  DX :  AX    Divisor	   AX	  ... DX
	//  AH :  AL    Divisor	   AL	  ... AH
	// src2  src1   src0      dst0       dst1 
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt1 = CAST2_USE(src[1]->node)->val;
		vt2 = CAST2_USE(src[2]->node)->val;

		vt3 = CAST2_DEF(dst[0]->node)->afterval;
		vt4 = CAST2_DEF(dst[1]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = ((vt2.byte << BYTE_SIZE) + vt1.byte - vt4.byte) / vt3.byte;
				break;
			case op_word:
				vt.word = ((vt2.word << WORD_SIZE) + vt1.word - vt4.word) / vt3.word;
				break;
			case op_dword:
				vt.dword = ((((long long)vt2.dword) << DWORD_SIZE) + vt1.dword - vt4.dword) / vt3.dword;
				break;
			default:
				break;
		}
		assert_val(src[0], vt, false);
	}

	if((!CAST2_USE(src[0]->node)->val_known || !CAST2_USE(src[1]->node)->val_known)
		&& CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt3 = CAST2_DEF(dst[0]->node)->afterval;
		vt4 = CAST2_DEF(dst[1]->node)->afterval;

		vtdiv = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt1.byte = (vt3.byte * vtdiv.byte + vt4.byte) % (1 << BYTE_SIZE);
				vt2.byte = (vt3.byte * vtdiv.byte + vt4.byte) / (1 << BYTE_SIZE);
				break;
			case op_word:
				vt1.word = (vt3.word * vtdiv.word + vt4.word) % (1 << WORD_SIZE);
				vt2.word = (vt3.word * vtdiv.word + vt4.word) / (1 << WORD_SIZE);
				break;
			case op_dword:
				vt1.dword = (((long long)vt3.dword) * vtdiv.dword + vt4.dword) % (((long long)1) << DWORD_SIZE);
				vt2.dword = (((long long)vt3.dword) * vtdiv.dword + vt4.dword) / (((long long)1) << DWORD_SIZE);
				break;
			default:
				break;
		}

		assign_use_value(src[0], vt1);
		assign_use_value(src[1], vt2);

		add_to_uselist(src[0], re_uselist);
		add_to_uselist(src[1], re_uselist);

	}

	if(CAST2_USE(src[0]->node)->val_known && CAST2_USE(src[1]->node)->val_known 
		&& !CAST2_USE(src[2]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& (CAST2_DEF(dst[1]->node)->val_stat & AfterKnown)){

		vt1 = CAST2_USE(src[1]->node)->val;
		vt2 = CAST2_USE(src[2]->node)->val;

		vt3 = CAST2_DEF(dst[0]->node)->afterval;
		vt4 = CAST2_DEF(dst[1]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = ((vt2.byte << BYTE_SIZE) + vt1.byte - vt4.byte) / vt3.byte;
				break;
			case op_word:
				vt.word = ((vt2.word << WORD_SIZE) + vt1.word - vt4.word) / vt3.word;
				break;
			case op_dword:
				vt.dword = ((((long long)(vt2.dword)) << DWORD_SIZE) + vt1.dword - vt4.dword) / vt3.dword;
				break;
			default:
				break;
		}

		assign_use_value(src[0], vt);

		add_to_uselist(src[0], re_uselist);
	}

	if(CAST2_USE(src[0]->node)->val_known && CAST2_USE(src[1]->node)->val_known 
		&& CAST2_USE(src[2]->node)->val_known 
		&& (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) || 
		    !(CAST2_DEF(dst[1]->node)->val_stat & AfterKnown))
		){

		vt1 = CAST2_USE(src[1]->node)->val;
		vt2 = CAST2_USE(src[2]->node)->val;

		vtdiv = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt3.byte = ((vt2.byte << BYTE_SIZE) + vt1.byte) / vtdiv.byte;
				vt4.byte = ((vt2.byte << BYTE_SIZE) + vt1.byte) % vtdiv.byte;
				break;
			case op_word:
				vt3.word = ((vt2.word << WORD_SIZE) + vt1.word) / vtdiv.word;
				vt4.word = ((vt2.word << WORD_SIZE) + vt1.word) % vtdiv.word;
				break;
			case op_dword:
				vt3.dword = ((((long long)vt2.dword) << DWORD_SIZE) + vt1.dword) / vtdiv.dword;
				vt4.dword = ((((long long)vt2.dword) << DWORD_SIZE) + vt1.dword) % vtdiv.dword;
				break;
			default:
				break;
		}
		assign_def_after_value(dst[0], vt3);
		assign_def_after_value(dst[1], vt4);

		add_to_deflist(dst[0], re_deflist);
		add_to_deflist(dst[1], re_deflist);
	}
}


void inc_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

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
				vt.byte = vs1.byte - 1;
				break;
			case op_word:
				vt.word = vs1.word - 1;
				break;
			case op_dword:
				vt.dword = vs1.dword - 1;
				break;
		}
		assert_val(src[0], vt, false);
	}

	if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs2 = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = vs2.byte + 1;
				break;
			case op_word:
				vt.word = vs2.word + 1;
				break;
			case op_dword:
				vt.dword = vs2.dword + 1;
				break;
		}
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		! CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = vs1.byte - 1;
				break;
			case op_word:
				vt.word = vs1.word - 1;
				break;
			case op_dword:
				vt.dword = vs1.dword - 1;
				break;
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}


#ifdef WITH_SOLVER
	inc_solver(inst, src, dst, nuse, ndef);
#endif
}


void dec_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
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
				vt.byte = vs1.byte + 1;
				break;
			case op_word:
				vt.word = vs1.word + 1;
				break;
			case op_dword:
				vt.dword = vs1.dword + 1;
				break;
		}
		assert_val(src[0], vt, false);
	}

	if (!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		CAST2_USE(src[0]->node)->val_known ) {

		vs2 = CAST2_USE(src[0]->node)->val;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = vs2.byte - 1;
				break;
			case op_word:
				vt.word = vs2.word - 1;
				break;
			case op_dword:
				vt.dword = vs2.dword - 1;
				break;
		}
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

	if ((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown) &&
		! CAST2_USE(src[0]->node)->val_known ) {

		vs1 = CAST2_DEF(dst[0]->node)->afterval;

		switch (CAST2_DEF(dst[0]->node)->operand->datatype) {
			case op_byte:
				vt.byte = vs1.byte + 1;
				break;
			case op_word:
				vt.word = vs1.word + 1;
				break;
			case op_dword:
				vt.dword = vs1.dword + 1;
				break;
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	}


#ifdef WITH_SOLVER
	//dec_solver(src, dst, nuse, ndef);
#endif

}

void shl_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	
	assert(nuse == 2 && ndef == 1);

	assert(CAST2_USE(src[1]->node)->operand->datatype == op_byte);

	vs1 = CAST2_USE(src[0]->node)->val;
	vs2 = CAST2_USE(src[1]->node)->val;

	switch(CAST2_USE(src[0]->node)->operand->datatype){

		case op_byte: 
			vt.byte = ((unsigned char)vs1.byte) << vs2.byte;
			break;	
		case op_word:	
			vt.word = ((unsigned short)vs1.word) << vs2.byte;
			break;	
		case op_dword:
			vt.dword = ((unsigned)vs1.dword)     << vs2.byte;
			break;	

		default:
			assert("Fuck you" && 0);
	}


	// check here
	if(CAST2_USE(src[0]->node)->val_known 
			&& CAST2_USE(src[1]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assert_val(dst[0], vt, false);
	}


	if(CAST2_USE(src[0]->node)->val_known 
			&& CAST2_USE(src[1]->node)->val_known 
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}


#ifdef WITH_SOLVER
//	shl_solver(src, dst, nuse, ndef);
#endif

}


void shr_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);
	assert(nuse == 2 && ndef == 1);

	vs1 = CAST2_USE(src[0]->node)->val;
	vs2 = CAST2_USE(src[1]->node)->val;

	if (CAST2_USE(src[1]->node)->operand->datatype != op_byte) {
		LOG(stdout, "LOG: wrong datatype from libdisas\n");
		switch (CAST2_USE(src[1]->node)->operand->datatype) {
			case op_dword:
				assert(vs2.dword < 0x100);
				break;
			default:
				assert(0);
				break;
		}

		CAST2_USE(src[1]->node)->operand->datatype = op_byte;
	}

	switch(CAST2_USE(src[0]->node)->operand->datatype){

		case op_byte:
			vt.byte = ((unsigned char)vs1.byte) >> vs2.byte;
			break;
		case op_word:
			vt.word = ((unsigned short)vs1.word) >> vs2.byte;
			break;
		case op_dword:
			vt.dword = ((unsigned)vs1.dword) >> vs2.byte;
			break;

		default:
			assert("Fuck you" && 0);
	}


	// check here
	if(CAST2_USE(src[0]->node)->val_known
			&& CAST2_USE(src[1]->node)->val_known
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assert_val(dst[0], vt, false);
	}


	if(CAST2_USE(src[0]->node)->val_known
			&& CAST2_USE(src[1]->node)->val_known
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}

#ifdef WITH_SOLVER
	shr_solver(src, dst, nuse, ndef);
#endif

}

void rol_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);
	
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = rol_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = rol_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_def_after_value(dst[0], vt);

		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_DEF(dst[0]->node)->afterval;
		vs2 = CAST2_USE(src[1]->node)->val;
		
		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = ror_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_use_value(src[0], vt);
		add_to_uselist(src[0], re_uselist);
	
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assert(0);
	}

#ifdef WITH_SOLVER
	//rol_solver(src, dst, nuse, ndef);
#endif

}

void ror_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst,src,dst,re_uselist, re_deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);
	
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = ror_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}
		assert_val(dst[0], vt, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = ror_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_def_after_value(dst[0], vt);

		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_DEF(dst[0]->node)->afterval;
		vs2 = CAST2_USE(src[1]->node)->val;
		
		switch(CAST2_DEF(dst[0]->node)->operand->datatype){
			case op_byte: 
				assert(0);
				break;	
			case op_word:	
				assert(0);
				break;	
			case op_dword:
				switch (CAST2_USE(src[1]->node)->operand->datatype) {
					case op_byte:
						vt.dword = rol_int(vs1.dword, vs2.byte);
						break;
					default:
						assert(0);
				}
				break;	
			default:
				assert("Fuck you" && 0);
		}

		assign_use_value(src[0], vt);

		add_to_uselist(src[0], re_uselist);
	
	}
	if(CAST2_USE(src[0]->node)->val_known 
		&& !CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assert(0);
	}

#ifdef WITH_SOLVER
//	ror_solver(src, dst, nuse, ndef);
#endif
}
