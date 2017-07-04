#include <xmmintrin.h>
#include "insthandler.h"
#include "reverse_exe.h"


void ptest_handler(re_list_t* instnode){
	test_handler(instnode);
}

void ptest_resolver(re_list_t* inst, re_list_t* deflist, re_list_t* uselist){
	test_resolver(inst, deflist, uselist);
}

void pxor_handler(re_list_t* instnode){

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

			if(same_reg(dst, src)){
				memset(&tempval, 0, sizeof(tempval));
				assign_def_after_value(def, tempval);
				//list_add(&def->deflist, &re_deflist.deflist);
				add_to_deflist(def, &re_deflist);
			}
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
		default:
			LOG(stdout, "dst type %d src type %d\n", dst->type, src->type);
			assert(0);
	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	
	pxor_post_heuristics(instnode, &re_instlist, &re_uselist, &re_deflist); 

	re_resolve(&re_deflist, &re_uselist, &re_instlist);

	print_info_of_current_inst(instnode);
}

void pxor_post_heuristics(re_list_t *instnode, re_list_t *instlist, re_list_t *uselist, re_list_t *deflist){

//	if(list_empty(&re_ds.head.umemlist)){

		val2addr_heuristics(uselist);	
//	}

}


void pxor_resolver(re_list_t* inst, re_list_t* deflist, re_list_t* uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	valset_u vs1, vs2, vt;
	bool sign_extend = false;

	traverse_inst_operand(inst,src,dst,uselist, deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);

	if ((CAST2_USE(src[0]->node)->operand->datatype > CAST2_USE(src[1]->node)->operand->datatype)
		&& (CAST2_USE(src[1]->node)->operand->datatype == op_byte)) {
		sign_extend = true;
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		if (sign_extend)
			sign_extend_valset(&vs2, CAST2_USE(src[0]->node)->operand->datatype);

		for(i = 0; i<4; i++ ){
			vt.dqword[i] = vs1.dqword[i] ^ vs2.dqword[i];
		}

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	} 

	if(CAST2_USE(src[0]->node)->val_known 
		&& !CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		for(i = 0; i<4; i++ ){
			vt.dqword[i] = vs1.dqword[i] ^ vs2.dqword[i];
		}
	
		assign_use_value(src[1], vt);	
		add_to_uselist(src[1], uselist);
	} 


	if(!CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[1]->node)->val;
		vs2 = CAST2_DEF(dst[0]->node)->afterval;

		if (sign_extend)
			sign_extend_valset(&vs1, CAST2_USE(src[0]->node)->operand->datatype);

		for(i = 0; i<4; i++ ){
			vt.dqword[i] = vs1.dqword[i] ^ vs2.dqword[i];
		}
		assign_use_value(src[0], vt);

		//list_add(&src[0]->uselist, &uselist->uselist);	
		add_to_uselist(src[0], uselist);
	}

//fix me here
//need to do some value assertion
	if(CAST2_USE(src[0]->node)->val_known 
		&& CAST2_USE(src[1]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		vs1 = CAST2_USE(src[0]->node)->val;
		vs2 = CAST2_USE(src[1]->node)->val;

		vt = CAST2_DEF(dst[0]->node)->afterval;

		for(i = 0; i<4; i++ ){
			assert(vt.dqword[i] == vs1.dqword[i] ^ vs2.dqword[i]);
		}
	}

}





void movdqu_handler(re_list_t * instnode){
	mov_handler(instnode);
}

void movdqu_resolver(re_list_t * inst, re_list_t* deflist, re_list_t * uselist){
	mov_resolver(inst, deflist, uselist);
}

//special instruction: only move the most significant bit of each byte.  
void pmovmskb_hanlder(re_list_t* instnode){

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
	
	if(get_operand_combine(inst) != dest_register_src_register)
		assert("Wrong Combination of Operands" && 0);


	def = add_new_define(dst);
	usesrc = add_new_use(src, Opd);
	
	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}


void pmovmskb_resolver(re_list_t* inst, re_list_t* deflist, re_list_t* uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, size, index;
	valset_u vd, vt;
	__m128i v128; 


	traverse_inst_operand(inst,src,dst,uselist, deflist, &nuse, &ndef);	
	assert(nuse == 1 && ndef == 1);

	if(!CAST2_USE(src[0]->node)->val_known)
		return;

	vt = CAST2_USE(src[0]->node)->val;
	v128 = _mm_setr_epi32(vt.dqword[0], vt.dqword[1], vt.dqword[2], vt.dqword[3]);

	 vd.dword = _mm_movemask_epi8(v128);
 
	if(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown){
		assert_val(dst[0], vd, false);	
	}else{
		assign_def_after_value(dst[0], vd);
		add_to_deflist(dst[0], deflist);
	}	
}

//this instruction compare the two operands 
//but also re-define the first operand
void pcmpeqb_handler(re_list_t *instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);

	print_operand_info(inst->operand_count, dst, src);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	

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

		default:
			assert(0);

	}

	//list_add(&instnode->instlist, &re_instlist.instlist);
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}

	
void pcmpeqb_resolver(re_list_t * inst, re_list_t* deflist, re_list_t * uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	__m128i msr1, msr2, mdst;

	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);


	if(!CAST2_USE(src[0]->node)->val_known || ! CAST2_USE(src[1]->node)->val_known){
		return; 
	}

	vs1 = CAST2_USE(src[0]->node)->val;
	vs2 = CAST2_USE(src[1]->node)->val;
	
	msr1 = _mm_setr_epi32(vs1.dqword[0], vs1.dqword[1], vs1.dqword[2], vs1.dqword[3]);

	msr2 = _mm_setr_epi32(vs2.dqword[0], vs2.dqword[1], vs2.dqword[2], vs2.dqword[3]);

	mdst = _mm_cmpeq_epi8(msr1, msr2);
	
	memcpy(&vt, &mdst, sizeof(valset_u));

	if(! (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	}else
		assert_val(dst[0], vt, false);
}


void pminub_handler(re_list_t* instnode){

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
	
	switch(get_operand_combine(inst)){
		
		case dest_register_src_register:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			usesrc = add_new_use(src, Opd);		
			break;

		case dest_register_src_expression:
			def = add_new_define(dst);
			usedst = add_new_use(dst, Opd);
			split_expression_to_use(dst);
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

void pminub_resolver(re_list_t * inst, re_list_t* deflist, re_list_t * uselist){

	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef, i;
	__m128i msr1, msr2, mdst;

	valset_u vs1, vs2, vt;

	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);	

	assert(nuse == 2 && ndef == 1);


	if(!CAST2_USE(src[0]->node)->val_known || ! CAST2_USE(src[1]->node)->val_known){
		return; 
	}

	vs1 = CAST2_USE(src[0]->node)->val;
	vs2 = CAST2_USE(src[1]->node)->val;
	
	msr1 = _mm_setr_epi32(vs1.dqword[0], vs1.dqword[1], vs1.dqword[2], vs1.dqword[3]);

	msr2 = _mm_setr_epi32(vs2.dqword[0], vs2.dqword[1], vs2.dqword[2], vs2.dqword[3]);

	mdst = _mm_min_epu8(msr1, msr2);
	
	memcpy(&vt, &mdst, sizeof(valset_u));

	if(! (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	}else
		assert_val(dst[0], vt, false);
}

void movaps_handler(re_list_t* instnode){
	mov_handler(instnode);
}


void movaps_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	mov_resolver(inst, re_deflist, re_uselist);
}


void movdqa_handler(re_list_t* instnode){
	mov_handler(instnode);
}

void movdqa_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	mov_resolver(inst, re_deflist, re_uselist);
}


void movq_handler(re_list_t* instnode){
	mov_handler(instnode);
}


void movq_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);

	//add pre heuristics

	// xmm, r/m32
	// r/m32, xmm
	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(dst[0], CAST2_USE(src[0]->node)->val, false);
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_USE(src[0]->node)->val;
		clean_valset(&vt, CAST2_USE(src[0]->node)->operand->datatype, false);

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		vt = CAST2_DEF(dst[0]->node)->afterval;

		if (CAST2_DEF(dst[0]->node)->operand->datatype >= CAST2_USE(src[0]->node)->operand->datatype) {
			assign_use_value(src[0], vt);
			add_to_uselist(src[0], re_uselist);
		}
	}

	//adding post heuristics 
}


void movlpd_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	bool isdstxmm;
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);

	// xmm, m64 : true
	// m64, xmm : false
	isdstxmm = (CAST2_DEF(dst[0]->node)->operand->type == op_register);

	if(CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		if (isdstxmm) {
			assert_val(src[0], CAST2_DEF(dst[0]->node)->afterval, false);
		} else {
			assert_val(dst[0], CAST2_USE(src[0]->node)->val, false);
		}
	}

	if(CAST2_USE(src[0]->node)->val_known 
		&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		if (!isdstxmm) {
			vt = CAST2_USE(src[0]->node)->val;
			assign_def_after_value(dst[0], vt);
			add_to_deflist(dst[0], re_deflist);
		}
	} 

	if(!CAST2_USE(src[0]->node)->val_known 
		&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		if (isdstxmm) {
			vt = CAST2_DEF(dst[0]->node)->afterval;
			assign_use_value(src[0], vt);
			add_to_uselist(src[0], re_uselist);
		}
	}
}


void pshufd_handler(re_list_t* instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst, *imm;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def,*usesrc;
	valset_u tempval; 

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	
	dst = x86_get_dest_operand(inst);
	src = x86_get_src_operand(inst);
	imm = x86_get_imm_operand(inst);


	convert_offset_to_exp(src);
	convert_offset_to_exp(dst);	

	//	for debugginf use	
	print_operand_info(inst->operand_count, dst, src, imm);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

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

		default:
			assert(0);
	}

	add_new_use(imm, Opd);

	add_to_instlist(instnode, &re_instlist);
	re_resolve(&re_deflist, &re_uselist, &re_instlist);

//print the final result of the analysis
	print_info_of_current_inst(instnode);
}

void pshufd_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u vd, vt;
	__m128i v128, mdst;
	int imm;

	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);
	
	assert(nuse == 2 && ndef ==1);

	imm = CAST2_USE(src[1]->node)->val.byte; 

	assert(imm == 0);	

	vt = CAST2_USE(src[0]->node)->val; 

	v128 = _mm_setr_epi32(vt.dqword[0], vt.dqword[1], vt.dqword[2], vt.dqword[3]);

	mdst = _mm_shuffle_epi32(v128, 0);	
	
	memcpy(&vd, &mdst, sizeof(valset_u));	

	if((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& CAST2_USE(src[0]->node)->val_known) {
		assert_val(dst[0], vd, false);
	}

	if(!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& CAST2_USE(src[0]->node)->val_known) {
		assign_def_after_value(dst[0], vd);
		add_to_deflist(dst[0], deflist);
	}
/*
 * 	maybe this case could also be resolved due to imm
	if((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& !CAST2_USE(src[0]->node)->val_known) {
	}
*/
}


void punpcklbw_handler(re_list_t *instnode){

	x86_insn_t *inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usedst, *usesrc;
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

//print the final result of the analysis
	print_info_of_current_inst(instnode);

}


void punpcklbw_resolver(re_list_t* inst, re_list_t *deflist, re_list_t *uselist){
	
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u vs1, vs2, vt;
	__m128i msr1, msr2, mdst;

	traverse_inst_operand(inst, src, dst, uselist, deflist, &nuse, &ndef);
	
	assert(nuse == 2 && ndef ==1);

	assert(CAST2_USE(src[0]->node)->operand->datatype == op_dqword);

	vs1 = CAST2_USE(src[0]->node)->val; 
	vs2 = CAST2_USE(src[1]->node)->val; 

	msr1 = _mm_setr_epi32(vs1.dqword[0], vs1.dqword[1], vs1.dqword[2], vs1.dqword[3]);

	msr2 = _mm_setr_epi32(vs2.dqword[0], vs2.dqword[1], vs2.dqword[2], vs2.dqword[3]);
	
	mdst = _mm_unpacklo_epi8(msr1, msr2);
	
	memcpy(&vt, &mdst, sizeof(valset_u));	

	if((CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& CAST2_USE(src[0]->node)->val_known
		&& CAST2_USE(src[1]->node)->val_known) {
		assert_val(dst[0], vt, false);
	}

	if(!(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)
		&& CAST2_USE(src[0]->node)->val_known
		&& CAST2_USE(src[1]->node)->val_known) {
		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], deflist);
	}
}
