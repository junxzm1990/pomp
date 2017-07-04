#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "reverse_exe.h"
#include "inst_opd.h"
#include "reverse_log.h"
#include "re_alias.h"
#include <setjmp.h>


#define REPLACE_HEAD(oldhead, newhead) \
	(oldhead)->next->prev = newhead;\
	(oldhead)->prev->next = newhead; 

static bool member_in_umemlist(re_list_t *umem){

	re_list_t* entry;

	list_for_each_entry(entry, &re_ds.head.umemlist, umemlist){
		if(entry == umem)
			return true;
	}

	return false;
}


static bool member_in_alias_umemlist(re_list_t *umem){

	re_list_t* entry;

	list_for_each_entry(entry, &re_ds.aliashead.umemlist, umemlist){
		if(entry == umem)
			return true;
	}

	return false;
}


void add_to_umemlist(re_list_t * exp){

	if(!member_in_umemlist(exp))
		list_add(&exp->umemlist, &re_ds.head.umemlist);
}


void remove_from_umemlist(re_list_t* exp){

	if(member_in_umemlist(exp))
		list_del(&exp->umemlist);
}


void add_to_alias_umemlist(re_list_t * exp){

	if(!member_in_alias_umemlist(exp))
		list_add(&exp->umemlist, &re_ds.aliashead.umemlist);
}


void remove_from_alias_umemlist(re_list_t* exp){
	if(member_in_alias_umemlist(exp))
		list_del(&exp->umemlist);
}

//check if there is any unknown memory write cannot be resolved between two targets
bool alias_between_two_targets(re_list_t *entry, re_list_t *target){

	int index;  

	if(!resolve_alias(target, entry))
		return true;

	return false; 		
}

bool obstacle_between_two_targets(re_list_t *listhead, re_list_t* entry, re_list_t *target){

	if(!check_next_unknown_write(listhead, entry, target))
		return false; 
	
  	return alias_between_two_targets(entry, target);	
} 

//target is the node added later
bool check_next_unknown_write(re_list_t *listhead, re_list_t *def, re_list_t *target){

	//check if there is any unknown write between def and target

	re_list_t* entry;
	re_list_t* head; 

	head = def ? def : listhead; 

	list_for_each_entry(entry, &target->list, list){
		if(entry == head)
			break;
			
		if(entry->node_type == DefNode && node_is_exp(entry, false) && !CAST2_DEF(entry->node)->address)
			return true;
	} 

	return false;
}

static void assign_elements_of_address(re_list_t* exp1, re_list_t* exp2, re_list_t* uselist){

	valset_u vt; 
	unsigned address;
	x86_op_t *opd;
	re_list_t * index1, *index2, *base1, *base2; 

	get_element_of_exp(exp1, &index1, &base1);
	get_element_of_exp(exp2, &index2, &base2);

//exp2 is the expression with known address 
	assert( index2 == NULL || CAST2_USE(index2->node)->val_known);
	assert( base2 == NULL || CAST2_USE(base2->node)->val_known);	

	address = exp2->node_type == UseNode ?  CAST2_USE(exp2->node)->address : CAST2_DEF(exp2->node)->address; 

	CAST2_DEF(exp1->node)->address = address; 

	switch(exp_addr_status(base1, index1)){

		case KBaseKIndex:	
			assert("fuck you" && 0);	
			break;

		case UBaseUIndex:
			break;

		case UBase:
			vt.dword = address - CAST2_USE(base1->node)->operand->data.expression.disp;	
			assign_use_value(base1, vt);
			add_to_uselist(base1, uselist);
			break;

		case UIndex:
			opd = CAST2_USE(index1->node)->operand;
			vt.dword = (address - opd->data.expression.disp)/(opd->data.expression.scale);
			assign_use_value(index1, vt);
			add_to_uselist(index1, uselist);

			break;

		case UBaseKIndex:
			opd = CAST2_USE(index1->node)->operand;
			vt.dword = address - CAST2_USE(index1->node)->val.dword * opd->data.expression.scale -
				opd->data.expression.disp;
			assign_use_value(base1, vt);
			add_to_uselist(base1, uselist);
			break;

		case KBaseUIndex:
			opd = CAST2_USE(index1->node)->operand;
			vt.dword = (address - CAST2_USE(base1->node)->val.dword - opd->data.expression.disp)/(opd->data.expression.scale);
			assign_use_value(index1, vt);
			add_to_uselist(index1, uselist);
			break;

		default:
			assert("Impossible" && 0);
			break;
	}
}

bool re_alias_resolve(re_list_t* exp1, re_list_t* exp2){


	valset_u vt; 
	re_list_t deflist, uselist, instlist;  	
	unsigned address, tempaddr;
	x86_op_t *opd;

	INIT_LIST_HEAD(&deflist.deflist);
	INIT_LIST_HEAD(&uselist.uselist);
	INIT_LIST_HEAD(&instlist.instlist);	

	re_list_t * index1, *index2, *base1, *base2; 

	get_element_of_exp(exp1, &index1, &base1);
	get_element_of_exp(exp2, &index2, &base2);

//exp2 is the expression with known address

	address = exp2->node_type == UseNode ?  CAST2_USE(exp2->node)->address : CAST2_DEF(exp2->node)->address;
	address += re_ds.alias_offset; 

	assert(address);

	switch(exp_addr_status(base1, index1)){
		case KBaseKIndex:	
			//check if two addresses are equal
			//if not, directly return; 
			//otherwise
			//assign address to the exp1
			//remove exp1 from umemlist
			opd = CAST2_DEF(exp1->node)->operand;
			
			tempaddr = base1 ? CAST2_USE(base1->node)->val.dword : 0;
			tempaddr += index1 ? CAST2_USE(index1->node)->val.dword * opd->data.expression.scale : 0; 

			tempaddr += opd->data.expression.disp; 
			tempaddr += op_with_gs_seg(opd) ? re_ds.coredata->corereg.gs_base : 0;  


			if(address != tempaddr){
				assert_address();
			}
			
			break;

		case UBaseUIndex:
			// do we need to set addres field for exp1?
			// if we do not, the memory expression later can't retrieve any value from coredump
			// only set address for this memory expression

			CAST2_DEF(exp1->node)->address = address;
			
			remove_from_umemlist(exp1);
			// set memory value
		/*

			if(assign_mem_val(exp1, &vt, &uselist)) {
				assign_def_after_value(exp1, vt);
				add_to_deflist(exp1, &deflist);
			}
		*/
			// remove from umemlist here
			break;

		case UBase:
			vt.dword = address - CAST2_USE(base1->node)->operand->data.expression.disp;	
			assign_use_value(base1, vt);
			add_to_uselist(base1, &uselist);

			// remove from umemlist here
			remove_from_umemlist(exp1);
			break;

		case UIndex:
			opd = CAST2_USE(index1->node)->operand;
			vt.dword = (address - opd->data.expression.disp)/(opd->data.expression.scale);
			assign_use_value(index1, vt);
			add_to_uselist(index1, &uselist);

			// remove from umemlist here
			remove_from_umemlist(exp1);
			break;

		case UBaseKIndex:

			opd = CAST2_USE(index1->node)->operand;
			vt.dword = address - CAST2_USE(index1->node)->val.dword * opd->data.expression.scale - opd->data.expression.disp;
			assign_use_value(base1, vt);
			add_to_uselist(base1, &uselist);
			// remove from umemlist here
			remove_from_umemlist(exp1);
			break;

		case KBaseUIndex:

			opd = CAST2_USE(index1->node)->operand;
			vt.dword = (address - CAST2_USE(base1->node)->val.dword - opd->data.expression.disp)/(opd->data.expression.scale);
			assign_use_value(index1, vt);
			add_to_uselist(index1, &uselist);
			// remove from umemlist here
			remove_from_umemlist(exp1);
			break;

		default:
			assert("Impossible" && 0);
			break;
	}

	re_resolve(&deflist, &uselist, &instlist);
}


//make a global copy of the mainlist and the umemlist
static void init_alias_config(re_t* oldre){

	INIT_LIST_HEAD(&re_ds.head.list);
	fork_corelist(&re_ds.head, &oldre->head);	

	// maintain umemlist in the old linked list

	INIT_LIST_HEAD(&re_ds.head.umemlist);
	fork_umemlist(&oldre->head);
}


static void save_re_ds(re_t *oldre) {
	memcpy(oldre, &re_ds, sizeof(re_t));
	
	REPLACE_HEAD((&re_ds.head.list), (&oldre->head.list));

	REPLACE_HEAD((&re_ds.head.umemlist), (&oldre->head.umemlist));
}


static void restore_re_ds(re_t *oldre) {
	memcpy(&re_ds, oldre, sizeof(re_t));

	REPLACE_HEAD((&oldre->head.list), (&re_ds.head.list));

	REPLACE_HEAD((&oldre->head.umemlist), (&re_ds.head.umemlist));
}


void inc_rec_count(){
	re_ds.rec_count++;
}


bool check_alias_pair(re_list_t* exp1, re_list_t* exp2){
	
	re_t oldre; 
	re_list_t *aexp1, *aexp2;
	int retval;

	if(exp2->node_type == UseNode && CAST2_USE(exp2->node)->address >= 0x804b650 && CAST2_USE(exp2->node)->address <= 0x804b66f)
		return false; 	


//heuristic here
#ifdef BIN_ALIAS
//this pair has been proved to be not alias
	if(search_pair(&re_ds.atroot, exp2->id, exp1->id))
		return false; 	
#endif


	printf("Current inst id is %d, source is %d and target is %d\n", re_ds.curinstid, find_inst_of_node(exp2)->id, find_inst_of_node(exp1)->id );

	if(find_inst_of_node(exp1)->id > re_ds.curinstid
		|| find_inst_of_node(exp2)->id > re_ds.curinstid)
		return true;

#ifdef WITH_SOLVER
	//check if the alias assumption violates the constraint system
	//take this as a fast path for alias check
	// if the constraint system tells non-alias, then quickly return...

	Z3_lbool aliascst1, aliascst2; 

	aliascst2 = check_alias_by_constraint(exp1, exp2, true, re_ds.alias_offset);

	if(aliascst2 == Z3_L_FALSE){
		return false; 
	}
#endif

#ifdef BIN_ALIAS
	if(!bin_alias_check(exp1, exp2))
		return false;
#endif


	
//store the re_ds structure 
//this must be done before any alias resolving
	save_re_ds(&oldre);

//copy the execution context: head 
	init_alias_config(&oldre);

	aexp1 = get_new_exp_copy(exp1);
	aexp2 = get_new_exp_copy(exp2);

	retval = setjmp(re_ds.aliasret);
	switch (retval) {
		case REC_ADD:
			inc_rec_count();

			if (re_ds.rec_count == REC_LIMIT) {
				longjmp(re_ds.aliasret, 2);
			}

			re_alias_resolve(aexp1, aexp2);

			//destroy the copied mainlist 
			delete_corelist(&re_ds.head);

			//recover the main data structure
			restore_re_ds(&oldre);

			return true; 

		case REC_DEC:
			delete_corelist(&re_ds.head);

			restore_re_ds(&oldre);

			return false; 

		case REC_LIM:
			delete_corelist(&re_ds.head);

			restore_re_ds(&oldre);

			return true; 

		default:
			assert(0);
			break;
	}
}

bool resolve_alias(re_list_t* exp, re_list_t *target){

	re_list_t * entry, *temp; 
	re_list_t * nextdef; 
	int dtype;

	if (re_ds.rec_count + 1  == REC_LIMIT)
		return false; 

	list_for_each_entry_safe(entry, temp, &re_ds.head.umemlist, umemlist){
		//all the unknown memory after nextdef
		if(target && node1_add_before_node2(entry, target))
			return true; 
		
		if(node1_add_before_node2(entry, exp)){

			if(!re_ds.resolving)
				return false;

//if these two cannot alias based on their constraints,then we can directly return
//take this as a cache based optimization

			if(check_alias_pair(entry, exp)){
				
				if(re_ds.rec_count == 0){
					printf("**************************** One pair of aliases cannot be resolved ****************************\n");
					print_instnode(find_inst_of_node(entry)->node);
					print_instnode(find_inst_of_node(exp)->node);
					printf("**************************** End of resolving one pair of aliases ****************************\n");
				}

				return false; 
			}
#ifdef BIN_ALIAS				
			else{

				if(re_ds.rec_count == 0)
					insert_pair(&re_ds.atroot, exp->id, entry->id);	
			}
#endif

#ifdef WITH_SOLVER
				//add the constraints that they are not alias
			if(!re_ds.rec_count){
				add_address_constraint(entry, exp, false, re_ds.alias_offset); 
			}
#endif

		}
	}
	return true; 
}	

void continue_exe_with_alias() {

	re_list_t *curinst = find_current_inst(&re_ds.head);
	int index, endindex;  

	index = CAST2_INST(curinst->node)->inst_index + 1;
	endindex = index + 50; 	

//	for (; index < re_ds.instnum; index++) {

	for (; index < endindex; index ++){
		curinst = add_new_inst(index);

		if (!curinst) {
			assert(0);
		}

		int handler_index = insttype_to_index(re_ds.instlist[index].type);
		if (handler_index >= 0) {
			inst_handler[handler_index](curinst);
		} else {
			assert(0);
		}

	}
	LOG(stdout, "Return from continue_exe_with_alias\n");
}
