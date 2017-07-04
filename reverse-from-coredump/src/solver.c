#ifdef WITH_SOLVER
#include "solver.h"
#include <stdio.h>
#include "reverse_exe.h"


Z3_ast mk_var(Z3_context ctx, const char * name, Z3_sort ty){
    Z3_symbol   s  = Z3_mk_string_symbol(ctx, name);
    return Z3_mk_const(ctx, s, ty);
}

void id_to_symname(int id, char * name){
	snprintf(name, SYMSIZE, "%x", id);	 
}

Z3_ast val_to_bv(valset_u val, size_t size){
	
	size_t temp_size; 
	size_t bv_size; 
	unsigned intval; 
	char tempval[SYMBUF];
	Z3_sort bv_sort; 	
	Z3_ast tempast, retast;
		
	retast = NULL;
	temp_size = 0;
	
	while(temp_size < size){

		memset(tempval, 0, SYMBUF);
		bv_size = size - temp_size >= 4 ? 4 : size - temp_size;					
		bv_sort = Z3_mk_bv_sort(re_ds.zctx, bv_size * BITOFBYTE);
		memcpy(&intval, ((void*)(&val)) + temp_size, VALUNITSIZE);
		snprintf(tempval, SYMSIZE, "%u", intval);
			
		tempast = Z3_mk_numeral(re_ds.zctx, tempval, bv_sort);

		if(!retast)
			retast = tempast;
		else{	
			retast = Z3_mk_concat(re_ds.zctx, tempast, retast);
		}
		temp_size += 4;  
	}
	return retast; 
}

bool adjust_use_constraint(re_list_t *node){

	char symname[SYMBUF];
	size_t symsize;
	Z3_sort bv_sort; 
	Z3_ast symbol;
	Z3_ast eqast;
	Z3_lbool proof; 
	use_node_t* use; 

	//disable constraint system during alias verification
	//will open later
	if(re_ds.rec_count)
		return false; 

	use = CAST2_USE(node->node);
	symsize = size_of_node(node);
	assert(symsize < 20);		

	//constraint is NULL
	if(use->constraint == NULL){

		if(use->val_known){
			symbol = val_to_bv(use->val, symsize);
			use->constant = true;
		} else{
			memset(symname, 0, SYMBUF);
			id_to_symname(node->id, symname);
			//make a constraint data type (a bit vector)
			//to save some troubles in the future
			bv_sort = Z3_mk_bv_sort(re_ds.zctx, symsize * BITOFBYTE);
			symbol = mk_var(re_ds.zctx, symname, bv_sort);
		}
		use->constraint = symbol;
		return true; 
	}else{
		//if the value of is known, we add the constant constraint
		if(!use->constant && use->val_known){
			symbol = val_to_bv(use->val, symsize);			
			eqast = Z3_mk_eq(re_ds.zctx, use->constraint, symbol);


			add_constraint(eqast);
			use->constant = true;	
		}
		return true;
	}
	return true; 
}

bool adjust_def_constraint(re_list_t * node){

	char symname[SYMBUF];
	size_t symsize;
	Z3_sort bv_sort; 
	Z3_ast symbol;
	Z3_ast eqast;
	Z3_lbool proof; 
	def_node_t * def; 

	//disable constraint system during alias verification
	//will open later
	if(re_ds.rec_count)
		return false; 

	def = CAST2_DEF(node->node);
	symsize = size_of_node(node);
	assert(symsize < 20);		

	//constraint on the before value is NULL
	if(def->beforecst == NULL){
		if(def->val_stat & BeforeKnown){
			symbol = val_to_bv(def->beforeval, symsize);
			def->beforeconst = true;

		}else{
			memset(symname, 0, SYMBUF);
			symname[0] = 'x';

			id_to_symname(node->id, symname + 1);
			bv_sort = Z3_mk_bv_sort(re_ds.zctx, symsize * BITOFBYTE);
			symbol = mk_var(re_ds.zctx, symname, bv_sort);
		}
		def->beforecst = symbol;
	}else{
		if(!def->beforeconst && (def->val_stat & BeforeKnown)){

			symbol = val_to_bv(def->beforeval, symsize);
						
			eqast = Z3_mk_eq(re_ds.zctx, def->beforecst, symbol);

			add_constraint(eqast);
			def->beforeconst = true;
		}
	}

	//if the constraint on the after value is unknown
	if(def->aftercst == NULL){
		if(def->val_stat & AfterKnown){
			symbol = val_to_bv(def->afterval, symsize);
			def->afterconst = true;
		}else{
			memset(symname, 0, SYMBUF);
			symname[0] = 'y';
			id_to_symname(node->id, symname + 1);
			//make a constraint data type (a bit vector)
			//to save some troubles in the future
			bv_sort = Z3_mk_bv_sort(re_ds.zctx, symsize * BITOFBYTE);
			symbol = mk_var(re_ds.zctx, symname, bv_sort);
		}
		def->aftercst = symbol;
	}else{
		if( !def->afterconst && (def->val_stat & AfterKnown)){
			//constraint already exist
			//check if we need to make an update
			symbol = val_to_bv(def->afterval, symsize);			
			eqast = Z3_mk_eq(re_ds.zctx, def->aftercst, symbol);

			add_constraint(eqast);
			def->afterconst = true;
		}
	}
	return true; 
}

Z3_lbool constraint_check(Z3_ast assert){

	Z3_lbool proof; 

//using push and pop to keep the correct constraints from being polluted
	Z3_solver_push(re_ds.zctx, re_ds.solver);	
	Z3_solver_assert(re_ds.zctx, re_ds.solver, assert);
	proof = Z3_solver_check(re_ds.zctx, re_ds.solver);
	Z3_solver_pop(re_ds.zctx, re_ds.solver, 1);	

	return proof;
}

void add_constraint(Z3_ast constraint){
	Z3_solver_assert(re_ds.zctx, re_ds.solver, constraint);
//	assert(Z3_solver_check(re_ds.zctx, re_ds.solver) == Z3_L_TRUE);
}


Z3_lbool check_alias_by_constraint(re_list_t* node1, re_list_t*node2, bool alias, int offset){

	Z3_ast addrcst1, addrcst2; 
	
	if(node1->node_type == UseNode){
		addrcst1 = CAST2_USE(node1->node)->addresscst; 

	}else{
		addrcst1 = CAST2_DEF(node1->node)->addresscst; 
	}	
	
	if(node2->node_type == UseNode){
		addrcst2 = CAST2_USE(node2->node)->addresscst; 
	}else{
		addrcst2 = CAST2_DEF(node2->node)->addresscst; 
	}	
	
	if(!alias)	
		return constraint_check(Z3_mk_not(re_ds.zctx, Z3_mk_eq(re_ds.zctx, addrcst1, addrcst2)));	
	else 
		return constraint_check(Z3_mk_eq(re_ds.zctx, addrcst1, addrcst2));	
}


//alwasy assume node1 has unknown address and node2 has known address
//alias specifies if assuming the two nodes are aliases or otherwise
//offset for alias offset
void add_address_constraint(re_list_t* node1, re_list_t* node2, bool alias, int offset){

	Z3_ast addrcst1, addrcst2; 
	Z3_ast offsetast; 
	valset_u offval;



	
	offval.dword = offset; 
	offsetast = val_to_bv(offval, sizeof(unsigned));


	if(node1->node_type == UseNode){
		addrcst1 = CAST2_USE(node1->node)->addresscst; 

	}else{
		addrcst1 = CAST2_DEF(node1->node)->addresscst; 
	}	
	
	if(node2->node_type == UseNode){
		addrcst2 = CAST2_USE(node2->node)->addresscst; 

	}else{
		addrcst2 = CAST2_DEF(node2->node)->addresscst; 
	}	




	if(!alias){
		add_constraint(Z3_mk_not(re_ds.zctx, Z3_mk_eq(re_ds.zctx, addrcst1, Z3_mk_bvadd(re_ds.zctx, addrcst2, offsetast))));	

	}
	else{ 
		add_constraint(Z3_mk_eq(re_ds.zctx, addrcst1, Z3_mk_bvadd(re_ds.zctx, addrcst2, offsetast)));	
	}
}

void add_solver(re_list_t* inst, re_list_t **src, re_list_t **dst, int nuse, int ndef){

	Z3_ast addend1, addend2; 
	Z3_ast addast;
	size_t size1, size2; 
	
	//if so, the constraint by semantics has been captured
	if(CAST2_INST(inst->node)->constraint)
		return; 

	//assert the size of sources and destinations
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	//assert the size relation between two sources
	assert(size1 >= size2);
	
	addend1 = CAST2_USE(src[0]->node)->constraint;
	addend2 = CAST2_USE(src[1]->node)->constraint;

	//make sure the two bv sources share the same bv type
	//also make sure it is sign-extended, as required by the X86 set
	if(size1 > size2){
		addend2 = Z3_mk_sign_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, addend2);
	}

	addast = Z3_mk_bvadd(re_ds.zctx, addend1, addend2);
	//add constraint that the added value equels to the destination
	CAST2_INST(inst->node)->constraint = Z3_mk_eq(re_ds.zctx, addast, CAST2_DEF(dst[0]->node)->aftercst);

	add_constraint(CAST2_INST(inst->node)->constraint);
}

//inc the constraint of src by 1
void inc_solver(re_list_t* inst, re_list_t **src, re_list_t **dst, int nuse, int ndef){

	Z3_ast addend1, addend2, incast, dstast; 
	Z3_ast addast;
	size_t size1, size2; 
	valset_u astval;
	
	if(CAST2_INST(inst->node)->constraint)
		return; 
	

	//assert the size of sources and destinations
	assert(nuse == 1 && ndef == 1);
	size1 = size_of_node(src[0]);	
	addend1 = CAST2_USE(src[0]->node)->constraint;

	memset(&astval, 0, sizeof(valset_u));
	astval.byte = 1;
	addend2 = val_to_bv(astval, size1);

	incast = Z3_mk_bvadd(re_ds.zctx, addend1, addend2);

	//Increment constraint: the use constraint plus 1 = the destination constraint
	dstast = CAST2_DEF(dst[0]->node)->aftercst;

	//the destination is the summit of two sources 		
	CAST2_INST(inst->node)->constraint = Z3_mk_eq(re_ds.zctx, incast, dstast);

	add_constraint(CAST2_INST(inst->node)->constraint);
}

void sub_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef){

	Z3_ast subend1, subend2; 
	Z3_ast subast;
	size_t size1, size2; 

	//assert the size of sources and destinations
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	//assert the size relation between two sources
	assert(size1 >= size2);
	
	subend1 = CAST2_USE(src[0]->node)->constraint;
	subend2 = CAST2_USE(src[1]->node)->constraint;

	//make sure the two bv sources share the same bv type
	//also make sure it is sign-extended, as required by the X86 set
	if(size1 > size2){
		subend2 = Z3_mk_sign_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, subend2);
	}

	subast = Z3_mk_bvsub(re_ds.zctx, subend1, subend2);

	//add constraint that the added value equels to the destination
	add_constraint(Z3_mk_eq(re_ds.zctx, subast, CAST2_DEF(dst[0]->node)->aftercst));
}

//inc the constraint of src by 1
void dec_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef){

	Z3_ast subend1, subend2, decast, dstast; 
	Z3_ast subast;
	size_t size1, size2; 
	valset_u astval;

	//assert the size of sources and destinations
	assert(nuse == 1 && ndef == 1);
	size1 = size_of_node(src[0]);	
	subend1 = CAST2_USE(src[0]->node)->constraint;

	memset(&astval, 0, sizeof(valset_u));
	astval.byte = 1;
	subend2 = val_to_bv(astval, size1);

	decast = Z3_mk_bvsub(re_ds.zctx, subend1, subend2);

	//Increment constraint: the use constraint plus 1 = the destination constraint
	dstast = CAST2_DEF(dst[0]->node)->aftercst;

	//the destination is the summit of two sources 		
	add_constraint(Z3_mk_eq(re_ds.zctx, decast, dstast));
}

void shl_solver(re_list_t** src, re_list_t**dst, int nuse, int ndef){

	Z3_ast shlend1, shlend2, shlast, dstast;	
	size_t size1, size2; 
	
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	assert(size1 >= size2);
	
	shlend1 = CAST2_USE(src[0]->node)->constraint;
	shlend2 = CAST2_USE(src[1]->node)->constraint;

	if(size1 > size2){
		shlend2 = Z3_mk_zero_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, shlend2);
	}

	shlast =  Z3_mk_bvshl(re_ds.zctx, shlend1, shlend2);

	dstast = CAST2_DEF(dst[0]->node)->aftercst;

//the destination is the summit of two sources 		
	add_constraint( Z3_mk_eq(re_ds.zctx, shlast, dstast));
}

void shr_solver(re_list_t** src, re_list_t**dst, int nuse, int ndef){

	Z3_ast shrend1, shrend2, shrast, dstast;	
	size_t size1, size2; 
	
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	assert(size1 >= size2);
	
	shrend1 = CAST2_USE(src[0]->node)->constraint;
	shrend2 = CAST2_USE(src[1]->node)->constraint;

	if(size1 > size2){
		shrend2 = Z3_mk_zero_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, shrend2);
	}

	shrast =  Z3_mk_bvlshr(re_ds.zctx, shrend1, shrend2);

	dstast = CAST2_DEF(dst[0]->node)->aftercst;

//the destination is the summit of two sources 		
	add_constraint(Z3_mk_eq(re_ds.zctx, shrast, dstast));
}


void rol_solver(re_list_t** src, re_list_t**dst, int nuse, int ndef){

	Z3_ast rolend1, rolend2, rolast, dstast;	
	size_t size1, size2; 
	
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	assert(size1 >= size2);
	
	rolend1 = CAST2_USE(src[0]->node)->constraint;
	rolend2 = CAST2_USE(src[1]->node)->constraint;

	if(size1 > size2){
		rolend2 = Z3_mk_zero_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, rolend2);
	}

	rolast =  Z3_mk_ext_rotate_left(re_ds.zctx, rolend1, rolend2);

	dstast = CAST2_DEF(dst[0]->node)->aftercst;

//the destination is the summit of two sources 		
	add_constraint(Z3_mk_eq(re_ds.zctx, rolast, dstast));
}

void ror_solver(re_list_t** src, re_list_t**dst, int nuse, int ndef){

	Z3_ast rorend1, rorend2, rorast, dstast;	
	size_t size1, size2; 
	
	assert(nuse == 2 && ndef == 1);
	size1 = size_of_node(src[0]);
	size2 = size_of_node(src[1]);
	assert(size1 >= size2);
	
	rorend1 = CAST2_USE(src[0]->node)->constraint;
	rorend2 = CAST2_USE(src[1]->node)->constraint;

	if(size1 > size2){
		rorend2 = Z3_mk_zero_ext(re_ds.zctx, (size1-size2) * BITOFBYTE, rorend2);
	}

	rorast =  Z3_mk_ext_rotate_right(re_ds.zctx, rorend1, rorend2);

	dstast = CAST2_DEF(dst[0]->node)->aftercst;

//the destination is the summit of two sources 		
	add_constraint(Z3_mk_eq(re_ds.zctx, rorast, dstast));
}
#endif
