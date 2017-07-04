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
#include "re_alias.h"
#include "reverse_log.h"
#include "inst_opd.h"
#include <setjmp.h>

#define REPLACE_HEAD(oldhead, newhead) \
	oldhead->next->prev = newhead;\
	oldhead->prev-Next = newhead; 

bool assert_val(re_list_t* node, valset_u vt, bool before){

	if(node->node_type == UseNode){

		use_node_t * use = node->node;
	
		if(use->usetype != Opd){
			if (use->val.dword != vt.dword) {
				assert(re_ds.rec_count);
				longjmp(re_ds.aliasret, 1);
			}
			return true;
		}

		switch(use->operand->datatype){

			case op_byte:
				if(use->val.byte != vt.byte) {
					assert(re_ds.rec_count);
					longjmp(re_ds.aliasret, 1);
				}
				break;

			case op_word:		
				if(use->val.word != vt.word) {
					assert(re_ds.rec_count);
					longjmp(re_ds.aliasret, 1);
				}
				break;

			case op_dword:
				
				if(use->val.dword != vt.dword) {
				
					if(!re_ds.rec_count)	
						assert(0);

					longjmp(re_ds.aliasret, 1);
				}
				break;
						
			case op_qword:
				if (memcmp(use->val.qword, vt.qword, 2*sizeof(long))) {

					assert(re_ds.rec_count);

					longjmp(re_ds.aliasret, 1);
				}
				break;
			case op_ssimd:
			case op_dqword:
				
				if(memcmp(use->val.dqword, vt.dqword, 4*sizeof(long))){

					if(!re_ds.rec_count)
						assert(0);

					longjmp(re_ds.aliasret, 1);
				}
				break;
			
			default:
				assert(0);
				return false; 
		}
	}	

	if(node->node_type == DefNode){
		def_node_t * def = node->node;
		valset_u vd = before ? def->beforeval : def->afterval; 	
		switch(def->operand->datatype){

			case op_byte:
				if(vd.byte != vt.byte) {
					assert(re_ds.rec_count);
					longjmp(re_ds.aliasret, 1);
				}
				break;

			case op_word:		
				if(vd.word != vt.word) {
					longjmp(re_ds.aliasret, 1);
				}
				break;

			case op_dword:
				if(vd.dword != vt.dword) {
						
					//assert(re_ds.rec_count);
					if(!re_ds.rec_count)
						assert(0);						

					longjmp(re_ds.aliasret, 1);
				}
				break;
				
			case op_qword:
				if(memcmp((void*)vd.qword, (void*)vt.qword, sizeof(vd.qword))){


					assert(re_ds.rec_count);

                                        longjmp(re_ds.aliasret, 1);
				}
			
				break;
		
			case op_ssimd:
			case op_dqword:
				if(memcmp((void*)vd.dqword, (void*)vt.dqword, sizeof(vd.dqword))){


					assert(re_ds.rec_count);

                                        longjmp(re_ds.aliasret, 1);
				}
			
				break;


			default:
				assert(0);
				return false; 
		}
	}	
}


void assert_address() {
	longjmp(re_ds.aliasret, 1);
}


re_list_t* get_new_exp_copy(re_list_t* exp){

	re_list_t * entry;

	list_for_each_entry(entry, &re_ds.head.list, list){
		if(entry->id == exp->id)
			return entry;
	}
	assert("Fuck you" && 0);
	return NULL;
}

void fork_umemlist(re_list_t * head){

	re_list_t *entry, *umem; 

	list_for_each_entry_reverse(entry, &head->umemlist, umemlist){
		umem = get_new_exp_copy(entry);
		list_add(&umem->umemlist, &re_ds.head.umemlist);
	}
}


void fork_corelist(re_list_t *newhead, re_list_t *oldhead) {
	re_list_t *entry;
	re_list_t *newnode;
	def_node_t * def; 
	use_node_t * use;
	inst_node_t * inst; 

	list_for_each_entry_reverse(entry, &oldhead->list, list) {
		newnode = (re_list_t *)malloc(sizeof(re_list_t));	
		if (!newnode) {
			assert("malloc failed" && 0);
		}

		memcpy(newnode, entry, sizeof(re_list_t));

		switch(entry->node_type){
	
			case DefNode:

				def = (def_node_t*)malloc(sizeof(def_node_t));
				if (!def) {
					assert("malloc failed" && 0);
				}

				memcpy(def, entry->node, sizeof(def_node_t));
				newnode->node = def; 
				break;

			case UseNode:
				
				use = (use_node_t*)malloc(sizeof(use_node_t));
				if (!use) {
					assert("malloc failed" && 0);
				}

				memcpy(use, entry->node, sizeof(use_node_t));
				newnode->node = use; 
				break;

			case InstNode:
	
				inst = (inst_node_t*)malloc(sizeof(inst_node_t));
				if (!inst) {
					assert("malloc failed" && 0);
				}

				memcpy(inst, entry->node, sizeof(inst_node_t));
				newnode->node = inst; 
				break;

			default:
				assert("Fuck you" && 0);
				break;
		}
		list_add(&newnode->list, &newhead->list);
	}
}


void delete_corelist(re_list_t *head) {
	re_list_t *entry, *temp;
	list_for_each_entry_safe(entry, temp, &head->list, list) {
		list_del(&entry->list);
		free(entry->node);
		free(entry);
		entry = NULL;
	}
}


void get_element_of_exp(re_list_t* exp, re_list_t ** index, re_list_t ** base){

	re_list_t* entry;
	*index = NULL;
	*base = NULL;

	list_for_each_entry_reverse(entry, &exp->list, list){

		if(entry->node_type != UseNode)
			return;
		
		if(CAST2_USE(entry->node)->usetype == Opd)
			return; 

		switch(CAST2_USE(entry->node)->usetype){
		
			case Index:
				*index = entry;
				break;
			
			case Base:
				*base = entry;
				break;
			
			case Opd:
				break;

			default:
				return ;
		}

	}
}

re_list_t *get_exp_by_element(re_list_t *elem) {
	assert(elem->node_type == UseNode);
	re_list_t* entry;
	list_for_each_entry(entry, &elem->list, list){
		if ((entry->node_type == UseNode) && (CAST2_USE(entry->node)->usetype != Opd))
			continue;
		if (entry->node_type == UseNode) {
			if (CAST2_USE(entry->node)->operand == CAST2_USE(elem->node)->operand)
				return entry;
		} else if (entry->node_type == DefNode) {
			if (CAST2_DEF(entry->node)->operand == CAST2_USE(elem->node)->operand)
				return entry;
		} else {
			assert(0);
		}
	}
	return NULL;
}

enum addrstat exp_addr_status(re_list_t* base, re_list_t * index){

	if(!index && !base)
		return NBaseNIndex;

	if(!index && base){
		if(CAST2_USE(base->node)->val_known)
			return KBaseKIndex;
		return UBase;
	}

	if(index && !base){
		if(CAST2_USE(index->node)->val_known)
			return KBaseKIndex;
		return UIndex; 	
	}

	if(CAST2_USE(index->node)->val_known && CAST2_USE(base->node)->val_known)
		return KBaseKIndex;

	if(!CAST2_USE(index->node)->val_known && !CAST2_USE(base->node)->val_known)
		return UBaseUIndex;

	if(CAST2_USE(index->node)->val_known && !CAST2_USE(base->node)->val_known)
		return UBaseKIndex;

	if(!CAST2_USE(index->node)->val_known && CAST2_USE(base->node)->val_known)
		return KBaseUIndex;
}


re_list_t *find_current_inst(re_list_t *listhead) {
	re_list_t *entry;
	list_for_each_entry(entry, &listhead->list, list) {
		if (entry->node_type != InstNode) continue;
		return entry;
	}
	assert("No any instruction in the list" && 0);
	return NULL;
}


bool ok_to_check_alias(re_list_t *exp) {

	re_list_t *instnode;
	x86_insn_t *inst;

	instnode = find_inst_of_node(exp);
	if (instnode) {
		inst = re_ds.instlist+CAST2_INST(instnode->node)->inst_index;
		if (strcmp(inst->mnemonic, "lea") == 0) {
			//LOG(stdout, "LOG: src operand of lea has no need to retrieve memory value\n");
			return false;
		}
	} else {
		assert("No corresponding instruction" && 0);
	}

	return true;
}





