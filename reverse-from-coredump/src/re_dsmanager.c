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
#include "solver.h"
#include "bin_alias.h"


re_list_t * find_next_def_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_next_def_of_use")));

re_list_t * find_prev_def_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_prev_def_of_use")));

re_list_t * find_next_use_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_next_use_of_use")));

re_list_t * find_prev_use_of_def(re_list_t *def, int *type) __attribute__ ((alias("find_prev_use_of_use")));


unsigned maxfuncid(void){

	unsigned id;
	re_list_t* entry;

	id = 0; 
	list_for_each_entry(entry, &re_ds.head.list, list){
		if(entry->node_type != InstNode)
			continue; 
		id = CAST2_INST(entry->node)->funcid > id ? CAST2_INST(entry->node)->funcid : id; 			
	}
	return id; 
}

re_list_t * lookfor_inst_nexttocall(re_list_t* instnode){

	re_list_t *entry; 
	inst_node_t *inst, *curinst;
	x86_insn_t *x86inst, *curx86inst;
	//to deal with the cases of recurssion
	int recnum; 
	
	recnum = 0;

	inst = CAST2_INST(instnode->node);
	x86inst = &re_ds.instlist[inst->inst_index];		

	list_for_each_entry(entry, &re_ds.head.list, list){		
		if(entry->node_type != InstNode)
			continue; 	

		curinst = CAST2_INST(entry->node);			
		curx86inst = &re_ds.instlist[curinst->inst_index];		


		if(curx86inst->addr == x86inst->addr)
			recnum++;

		//find the returned instruction and the recursive layer matches	
		if(x86inst->addr + x86inst->size == curx86inst->addr){
			if(!recnum)
				return entry;
			recnum--;
		}
	}

	return NULL;
}

void funcid_of_inst(re_list_t* instnode){

	re_list_t* entry, *previnstnode;
	inst_node_t* previnst; 	
	inst_node_t* inst;
	x86_insn_t *x86inst; 
	x86_insn_t *prevx86inst; 

	inst = CAST2_INST(instnode->node);

	if(list_empty(&re_ds.head.list)){
		inst->funcid = 0;
		goto adjust_boundary;
	}

	//find the last instruction 
	list_for_each_entry(entry, &re_ds.head.list, list){
		if(entry->node_type != InstNode)
			continue; 
		
		previnst = CAST2_INST(entry->node);
		break;
	}

	x86inst = &re_ds.instlist[inst->inst_index];
	prevx86inst = &re_ds.instlist[previnst->inst_index];

	//determine the function id based on the instruction type	
	switch(x86inst->type){
		//if this is return, as we are looking at the trace reversely, 
		//then a new function start
		case insn_return:
			inst->funcid = maxfuncid() + 1;
			break;
		case insn_call:

			previnstnode = lookfor_inst_nexttocall(instnode);
			if(!previnstnode){
				inst->funcid = maxfuncid() + 1;		
				print_instnode(inst);
				//assert(0);
				break;
			}

			previnst = CAST2_INST(lookfor_inst_nexttocall(instnode)->node);
			inst->funcid = previnst->funcid;	
			break;
		case insn_callcc:
			assert(0);
			break;

		//not special, simply classify it to the previous instruction
		default:
			inst->funcid = previnst->funcid;
			break;
	}

adjust_boundary:

#ifdef BIN_ALIAS
	adjust_func_boundary(instnode);
#endif
	return;
}


static int adjust_val_offset(re_list_t* entry, int type){

	int regid;
//use node 
	if(entry->node_type == UseNode){

		if(CAST2_USE(entry->node)->usetype == Opd && CAST2_USE(entry->node)->operand->type == op_register)
				regid = CAST2_USE(entry->node)->operand->data.reg.id;

			if(CAST2_USE(entry->node)->usetype == Base)
				regid = CAST2_USE(entry->node)->operand->data.expression.base.id;
			if(CAST2_USE(entry->node)->usetype == Index)
				regid = CAST2_USE(entry->node)->operand->data.expression.index.id;
	}
	
	if(entry->node_type == DefNode){
		if(CAST2_DEF(entry->node)->operand->type  == op_register)
				regid = CAST2_DEF(entry->node)->operand->data.reg.id;
	}


	if(type == SUB && (regid == get_ah_id() || regid == get_bh_id() || regid == get_ch_id() || regid == get_dh_id()))
		return 1; 

	return 0;
}



//get the value for a new use whose address is known 
//the use must be an expression
//if the use is a register, assignment to it will occur in add_new_use
static bool assign_use_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){

//basic logic
//get the value for the use byte by byte 
//for each byte, there are four different ways
//1. Check next def  
//2. Check next use
//3. Check prev def
//4. Check prev use
//attention, must take care of the unknown memory write between any memory accesses

	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	x86_op_t tmpopd; 
	x86_op_t *oriopd;	
	use_node_t* use;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == UseNode);

	use = CAST2_USE(exp->node);
	memsize = translate_datatype_to_byte(use->operand->datatype);
	oriaddr = use->address;

	oriopd = use->operand; 
	memcpy(&tmpopd, use->operand, sizeof(x86_op_t));		

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){

////////very important here!
		re_ds.alias_offset = index;
//////// 


//get the next define for one byte and restore the contexts
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		use->operand->datatype = op_byte; 
		nextdef = find_next_def_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

	// the base for alias check is the exp
	// so the address offset for check is the index here		

		if(nextdef && !(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown))
			goto nextuse;

		if(obstacle_between_two_targets(&re_ds.head, nextdef, exp))
			goto nextuse;  

		//get one byte from core dump
		if(!nextdef){

			//get one byte for the current address
			
			use->operand = &tmpopd; 
			use->address = oriaddr + index; 
			use->operand->datatype = op_byte; 
						
			if (get_value_from_coredump(exp, &tv) == BAD_ADDRESS) {
				use->address = oriaddr; 
				use->operand = oriopd;
				assert_address();
			}

			//assign the byte to the corrsponding location 
			memcpy(((void*)rv) + index, &tv.byte, 1);
			use->address = oriaddr; 
			use->operand = oriopd;
			
			//one byte has been resolved; continue with the next byte
			continue; 
		}

//get the value for the current byte from the next define
		
		if(true){	
//take care of the address difference between the next define and the target
			int offset = index + oriaddr - CAST2_DEF(nextdef->node)->address; 
			void * copyaddr = ((void*)&CAST2_DEF(nextdef->node)->beforeval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

nextuse:				
		re_ds.alias_offset = index;

		use->operand = &tmpopd; 
		
		use->address = oriaddr + index; 
		use->operand->datatype = op_byte; 
		nextuse = find_next_use_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

		if(!nextuse)
			goto prevdef;

		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto prevdef; 
			
		if(!CAST2_USE(nextuse->node)->val_known)
			goto prevdef; 

		if(obstacle_between_two_targets(&re_ds.head, nextuse, exp))
			goto prevdef;  

		if(true){
			int offset = index + oriaddr - CAST2_USE(nextuse->node)->address;	
                        void * copyaddr = ((void*)&CAST2_USE(nextuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }

//is this really necessary?
prevdef:
	//now the previous define or use is the base for alias check
	//as we only get one byte, no need to add any offset for alias  
		re_ds.alias_offset = 0;
		
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		use->operand->datatype = op_byte; 
		prevdef = find_prev_def_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 

		//there is no previous define; then try to find the previous use
		if(!prevdef)
			goto prevuse; 

		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown))
			goto prevuse; 	

		if(obstacle_between_two_targets(&re_ds.head,exp, prevdef))
			goto prevuse;  

		if(true){
			int offset = index + oriaddr - CAST2_DEF(prevdef->node)->address;
			void * copyaddr = ((void*)&CAST2_DEF(prevdef->node)->afterval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

prevuse:		
		re_ds.alias_offset = 0;
		
		use->operand = &tmpopd; 
		use->address = oriaddr + index; 
		use->operand->datatype = op_byte; 
		prevuse = find_prev_use_of_use(exp, &dtype);
		use->address = oriaddr; 
		use->operand = oriopd; 


		if(!prevuse)
			goto out;

		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out;
		 
		if(!CAST2_USE(prevuse->node)->val_known)
			goto out; 	
		
		if(obstacle_between_two_targets(&re_ds.head, exp, prevuse))
			goto out;  

		if(true){
			int offset = index + oriaddr - CAST2_USE(prevuse->node)->address;
                        void * copyaddr = ((void*)&CAST2_USE(prevuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }
out:
		return false; 
	}

	re_ds.alias_offset = 0;
	return true; 
}


static bool assign_def_before_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){

	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	x86_op_t tmpopd; 
	x86_op_t *oriopd;	
	def_node_t* def;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == DefNode);

	def = CAST2_DEF(exp->node);
	memsize = translate_datatype_to_byte(def->operand->datatype);
	oriaddr = def->address;

	oriopd = def->operand; 
	memcpy(&tmpopd, def->operand, sizeof(x86_op_t));		
	def->operand = &tmpopd; 

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){

////////very important here!
		re_ds.alias_offset = 0;
//////// 
		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		def->operand->datatype = op_byte; 
		prevdef = find_prev_def_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!prevdef)
			goto prevuse; 

		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown))
			goto prevuse;

		if(obstacle_between_two_targets(&re_ds.head, exp, prevdef))
			goto prevuse;  

		if(true){
			int offset = index + oriaddr - CAST2_DEF(prevdef->node)->address;
			void * copyaddr = ((void*)&CAST2_DEF(prevdef->node)->afterval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

prevuse:		

		re_ds.alias_offset = 0;

		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		def->operand->datatype = op_byte; 
		prevuse = find_prev_use_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!prevuse)
			goto out;

		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out; 

		if(!CAST2_USE(prevuse->node)->val_known)
			goto out; 

		if(obstacle_between_two_targets(&re_ds.head, exp, prevuse))
			goto out;  

		if(true){
			int offset = index + oriaddr - CAST2_USE(prevuse->node)->address;
                        void * copyaddr = ((void*)&CAST2_USE(prevuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }
out:
		return false; 
	}

	re_ds.alias_offset = 0;
	return true; 
}

static bool assign_def_after_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){

	int dtype; 
	size_t memsize;
	unsigned index;  
	valset_u tv; 
	unsigned oriaddr;
	x86_op_t tmpopd; 
	x86_op_t *oriopd;	
	def_node_t* def;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse; 

	assert(exp->node_type == DefNode);

	def = CAST2_DEF(exp->node);
	memsize = translate_datatype_to_byte(def->operand->datatype);
	oriaddr = def->address;

	oriopd = def->operand; 
	memcpy(&tmpopd, def->operand, sizeof(x86_op_t));		
	def->operand = &tmpopd; 

//process the destination byte by byte; 
	for(index = 0; index < memsize; index++){

////////very important here!
		re_ds.alias_offset = index;
//////// 
		def->operand = &tmpopd; 

		def->address = oriaddr + index; 
		def->operand->datatype = op_byte; 
		nextdef = find_next_def_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 
	

		if(nextdef && !(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown))				goto nextuse;

	
		if(obstacle_between_two_targets(&re_ds.head, nextdef, exp))
			goto nextuse;  

		//get one byte from core dump
		if(!nextdef){

			def->operand = &tmpopd; 
			def->address = oriaddr + index; 
			def->operand->datatype = op_byte; 
						
			if (get_value_from_coredump(exp, &tv) == BAD_ADDRESS) {
				def->address = oriaddr; 
				def->operand = oriopd;
				assert_address();
			}

			memcpy(((void*)rv) + index,&tv.byte, 1);
			def->address = oriaddr; 
			def->operand = oriopd;

			continue; 
		}

		if(true){
			int offset = index + oriaddr - CAST2_DEF(nextdef->node)->address; 
			void * copyaddr = ((void*)&CAST2_DEF(nextdef->node)->beforeval) + offset; 
			memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
		}

nextuse:	
		re_ds.alias_offset = index;
			
		def->operand = &tmpopd; 
		def->address = oriaddr + index; 
		def->operand->datatype = op_byte; 
		nextuse = find_next_use_of_def(exp, &dtype);
		def->address = oriaddr; 
		def->operand = oriopd; 

		if(!nextuse)
			goto out;
		
		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto out; 

		if(!CAST2_USE(nextuse->node)->val_known)
			goto out; 	
		
		if(obstacle_between_two_targets(&re_ds.head, nextuse, exp))
			goto out;  
		
		if(true){
			int offset = index + oriaddr - CAST2_USE(nextuse->node)->address;	
                        void * copyaddr = ((void*)&CAST2_USE(nextuse->node)->val) + offset;
                        memcpy(((void*)rv) + index, copyaddr, 1);
			continue;
                }
out:
		return false; 
	}

	re_ds.alias_offset = 0;
	return true; 
}


bool assign_mem_val(re_list_t* exp, valset_u * rv, re_list_t* uselist){
	
	if(exp->node_type == UseNode)
		return assign_use_mem_val(exp, rv, uselist);

	return false; 
}

//get the size of operand pointed to by a node
size_t size_of_node(re_list_t* node){

	use_node_t* use; 
	def_node_t* def;

	if(node->node_type == UseNode){

		use = CAST2_USE(node->node);

		switch(use->usetype){
			case Opd:
				if(use->operand->type == op_expression){
					return translate_datatype_to_byte(use->operand->datatype);
				}

				if(use->operand->type == op_register){
					return use->operand->data.reg.size; 
				}

				if(use->operand->type == op_immediate){
					return translate_datatype_to_byte(use->operand->datatype);
				}
				//in fact, there is a problem here
				//cause for some instructions, such as rep movz, the size of destination is unknown 
				assert("FUck you here" && 0);

			case Base:
				return use->operand->data.expression.base.size;	

			case Index: 
				return use->operand->data.expression.index.size;
			default: 
				assert("Wrong use tyep" &&  0);	
		}
	}

	if(node->node_type == DefNode){

		def = CAST2_DEF(node->node);
			
		if(def->operand->type == op_expression){
			return translate_datatype_to_byte(def->operand->datatype);
		}

		if(def->operand->type == op_register){
			return def->operand->data.reg.size; 
		}
	}

	assert("You can only get size of use node or def node" && 0);
	return 0; 
}




//add new use to the main link; checked
re_list_t * add_new_use(x86_op_t * opd, enum u_type type){

	re_list_t * newnode;
	re_list_t * nextdef;
	use_node_t * newuse; 
	int alias_type;

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));
	if(!newnode){
		return NULL; 
	}

	newnode->id = re_ds.current_id; 
	re_ds.current_id++;	

	newuse = (use_node_t*)malloc(sizeof(use_node_t));	
	if(!newuse){
		free(newnode);
		return NULL;
	}

	memset(newuse, 0, sizeof(use_node_t));
	
	newuse->usetype = type;
	newuse->operand = opd; 
	newnode->node_type = UseNode;
	newnode->node = (void*)newuse;

#ifdef WITH_SOLVER
	//if we have no solver system, we do not add any constraints
	CAST2_USE(newnode->node)->constraint = NULL;
#endif

	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

	//the use is an immediate value; 
	if(opd->type == op_immediate){
		get_immediate_from_opd(opd, &newuse->val);
		newuse->val_known = true;
		goto solve; 
	}

	//check the next define
	nextdef = find_next_def_of_use(newnode, &alias_type);

	//check if the use has been killed before
	if(!nextdef){

		if (ok_to_get_value(newnode)) {
			//set up value for the use here!
			if (get_value_from_coredump(newnode, &newuse->val) == BAD_ADDRESS) {
				assert_address();
			}
			newuse->val_known = true;
		}
	}
	else{
//if this is really necessary? Well, I do not know yet...
		 if( (alias_type == EXACT || alias_type == SUPER) &&
			CAST2_DEF(nextdef->node)->val_stat & BeforeKnown){
			assign_use_value(newnode, CAST2_DEF(nextdef->node)->beforeval);
		}
	}

solve:
#ifdef WITH_SOLVER
	CAST2_USE(newnode->node)->addresscst = NULL;
	CAST2_USE(newnode->node)->constant = false;
	adjust_use_constraint(newnode); 
#endif
	return newnode; 
}


re_list_t * add_new_define(x86_op_t * opd){

	re_list_t * newnode;
	re_list_t * nextdef;
	def_node_t * newdef; 
	int type;

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));
	if(!newnode){
		return NULL; 
	}

	newnode->id = re_ds.current_id; 
	re_ds.current_id++;	

	newdef = (def_node_t*)malloc(sizeof(def_node_t));	
	if(!newdef){
		free(newnode);
		return NULL;
	}

	memset(newdef, 0, sizeof(def_node_t));
	newdef->operand = opd; 
	newnode->node_type = DefNode;
	newnode->node = (void*)newdef;

#ifdef WITH_SOLVER
// init the before and after constraints
	CAST2_DEF(newnode->node)->beforecst = NULL;
	CAST2_DEF(newnode->node)->aftercst = NULL;
#endif

	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

	nextdef = find_next_def_of_def(newnode, &type);

	//check if the use has been killed before
	if(!nextdef){
		if (ok_to_get_value(newnode)) {
			//set up value for the define here!
			//assign_def_after_value(newnode, get_value_from_coredump(newnode));
			if (get_value_from_coredump(newnode, &newdef->afterval) == BAD_ADDRESS) {
				assert_address();
			}
			newdef->val_stat |= AfterKnown; 
		} 
	}
	else{
		if((type == EXACT || type == SUPER) &&	
			CAST2_DEF(nextdef->node)->val_stat & BeforeKnown){
				assign_def_after_value(newnode, CAST2_DEF(nextdef->node)->beforeval);
		}
	}

#ifdef WITH_SOLVER
	CAST2_DEF(newnode->node)->addresscst = NULL;	
	CAST2_DEF(newnode->node)->beforeconst = false;	
	CAST2_DEF(newnode->node)->afterconst = false;	
	adjust_def_constraint(newnode);		
#endif

	return newnode; 
}

re_list_t * add_new_inst(unsigned index){

	re_list_t * newnode; 
	inst_node_t * newinst;  

	newnode = (re_list_t *)malloc(sizeof(re_list_t ));

	if(!newnode){
		return NULL; 
	}
	
	newnode->id = re_ds.current_id; 
	re_ds.current_id++;	

	newinst = (inst_node_t*)malloc(sizeof(inst_node_t));	

	if(!newinst){
		free(newnode);
		return NULL;
	}

	newinst->inst_index = index; 

#ifdef WITH_SOLVER
	newinst->constraint = NULL;
#endif

	newnode->node_type = InstNode;
	newnode->node = (void*)newinst;

	funcid_of_inst(newnode);
	//insert new node into main list
	list_add(&newnode->list, &re_ds.head.list);

	return newnode;
}

void assign_def_before_value(re_list_t * def, valset_u val){

	memcpy( &(CAST2_DEF(def->node)->beforeval), 
		&val, sizeof(val));   
	
	CAST2_DEF(def->node)->val_stat |= BeforeKnown;  

#ifdef DATA_LOGGED
	//check the resolved values against the ground truth log
	//to aid the debugging process
	//do not perform correctness check when verifying alias
		if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
			correctness_check(find_inst_of_node(def));	
#endif

}

void assign_def_after_value(re_list_t * def, valset_u val){

	if(!re_ds.rec_count && def->id == 65335)
		printf("Interesting here 2\n");

	memcpy(&(CAST2_DEF(def->node)->afterval), 
		&val, sizeof(val));   

	CAST2_DEF(def->node)->val_stat |= AfterKnown;  

#ifdef DATA_LOGGED
	//check the resolved values against the ground truth log
	//to aid the debugging process
	//do not perform correctness check when verifying alias
		if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
			correctness_check(find_inst_of_node(def));	
#endif
}

void assign_use_value(re_list_t *use, valset_u val) {



	if(use->id == 53089){
		printf("reached interesting point\n");
//		assert(0);
	}
	
	memcpy( &(CAST2_USE(use->node)->val), 
		&val, sizeof(val));   

	CAST2_USE(use->node)->val_known = true;  

#ifdef DATA_LOGGED
	//check the resolved values against the ground truth log
	//to aid the debugging process
	//do not perform correctness check when verifying alias
		if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
			correctness_check(find_inst_of_node(use));	
#endif
}

//search for the use corresponding before a specific define
static void def_before_pollute_use(re_list_t *def, re_list_t *re_instlist){

	re_list_t * node;
	re_list_t *inst;
	int type;

	list_for_each_entry_reverse(node, &def->list, list) {
		//reached the end
		if (node == &re_ds.head) 
			break;

		//it is an inst 
		if (node->node_type == InstNode) 
			continue;

		//encounter a redefine or a define with unknown address
		if (node->node_type == DefNode && compare_two_targets(def, node)) {
			break;
		}

		//define to a memory and there exist writing with unknown memory address
		if(node_is_exp(def, false) && node->node_type == DefNode && node_is_exp(node, false) && !CAST2_DEF(node->node)->address){
			break;
		}

		//if it is a use, then check if it has same ID with the define
		if (node->node_type == UseNode){ 

			type = compare_two_targets(def, node);

			//yes
			if((type == EXACT || type == SUPER)){ 
				//the use has unknown value, then pollute the define
				if(!CAST2_USE(node->node)->val_known){
					assign_use_value(node, CAST2_DEF(def->node)->beforeval);
					//add the inst
					inst = find_inst_of_node(node);
					if (!check_inst_resolution(inst)) {
						add_to_instlist(inst, re_instlist);
					}
				}//else, check if the use and the define are consistent
				else{
						assert_val(node, CAST2_DEF(def->node)->beforeval, true);
				}
			}
		}
	}
}


//search for the use corresponding after a specific define
static void def_after_pollute_use(re_list_t *def, re_list_t *re_instlist){

	re_list_t * node;
	re_list_t *inst;
	int type;


	list_for_each_entry(node, &def->list, list) {
		//reached the end
		if (node == &re_ds.head) 
			break;

		//it is an inst 
		if (node->node_type == InstNode) 
			continue;

		//encounter a redefine or a define with unknown address
		if (node->node_type == DefNode && compare_two_targets(def, node)) {
			break;
		}

		if(node_is_exp(def, false) && node->node_type == DefNode && node_is_exp(node, false) && !CAST2_DEF(node->node)->address){
			break;
		}

		//if it is a use, then check if it has same ID with the define
		if (node->node_type == UseNode){ 

			type = compare_two_targets(def, node);

			//yes
			if((type == EXACT || type == SUPER)){ 
				//the use has unknown value, then pollute the define
				if(!CAST2_USE(node->node)->val_known){
					assign_use_value(node, CAST2_DEF(def->node)->afterval);

					//add the inst
					inst = find_inst_of_node(node);
					if (!check_inst_resolution(inst)) {
						add_to_instlist_tail(inst, re_instlist);
					}


				}//else, check if the use and the define are consistent
				else{
						assert_val(node, CAST2_DEF(def->node)->afterval, true);
				}
			}
		}
	}
}



int compare_def_def(re_list_t *first, re_list_t *second) {
	def_node_t *firstd = (def_node_t*) first->node;
	def_node_t *secondd = (def_node_t*) second->node;	

	if(firstd->operand->type != secondd->operand->type) {
		return 0;
	}

	if(firstd->operand->type == op_register) {
		if (exact_same_regs(firstd->operand->data.reg, secondd->operand->data.reg)) {
			return EXACT;
		}
		
		if (reg1_alias_reg2(firstd->operand->data.reg, secondd->operand->data.reg)) {
			return SUB; 
		}

		if (reg1_alias_reg2(secondd->operand->data.reg, firstd->operand->data.reg)) {
			return SUPER; 
		}

		if (same_alias(firstd->operand->data.reg, secondd->operand->data.reg)) {

			if (firstd->operand->data.reg.size == secondd->operand->data.reg.size) {
				return 0;
			}

			if (firstd->operand->data.reg.size > secondd->operand->data.reg.size) {
				return SUPER;
			}

			return SUB;
		}
	}

	if(firstd->operand->type == op_expression){
		if(firstd->address == 0 || secondd->address == 0){			
			return 0;
		}

		size_t size1 = translate_datatype_to_byte(firstd->operand->datatype);
		size_t size2 = translate_datatype_to_byte(secondd->operand->datatype);
		if exact_same_mem(firstd->address, size1, secondd->address, size2) {
			return EXACT;
		}
		if subset_mem(firstd->address, size1, secondd->address, size2) {
			return SUB;
		}
		if superset_mem(firstd->address, size1, secondd->address, size2) {
			return SUPER;
		}
		if ( overlap_mem(firstd->address, size1, secondd->address, size2) ||
		     overlap_mem(secondd->address, size2, firstd->address, size1) ) {
			return OVERLAP;
		}
		
	}
	if (firstd->operand->type == op_offset) {
		if (op_with_gs_seg(firstd->operand) && op_with_gs_seg(secondd->operand)) {
			if (firstd->operand->data.offset != secondd->operand->data.offset) {
				return 0;
			} else {
				return EXACT;
			}
		}
		assert(0);
	}
	return 0;		
}

int compare_def_use(re_list_t *first, re_list_t *second) {
	def_node_t *firstd = (def_node_t *)first->node;
	use_node_t *secondu = (use_node_t*)second->node; 

	size_t size1, size2;

	size1 = translate_datatype_to_byte(firstd->operand->datatype);
	size2 = translate_datatype_to_byte(secondu->operand->datatype);

	switch(secondu->usetype){
		case Opd:

			if(firstd->operand->type != secondu->operand->type){
				return 0;
			}

			if(firstd->operand->type == op_register){
				if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.reg)) {
					return EXACT;
				}

				if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.reg)) {
					return SUB; 
				}
				if (reg1_alias_reg2(secondu->operand->data.reg, firstd->operand->data.reg)) {
					return SUPER; 
				}
				if (same_alias(firstd->operand->data.reg, secondu->operand->data.reg)) {

					if (firstd->operand->data.reg.size == secondu->operand->data.reg.size) {
						return 0;
					}

					if (firstd->operand->data.reg.size > secondu->operand->data.reg.size) {
						return SUPER;
					}

					return SUB;					
				}
			}

			if(firstd->operand->type == op_expression){

				if(firstd->address == 0 || secondu->address == 0)	
					return 0;
				if exact_same_mem(firstd->address, size1, secondu->address, size2) {
					return EXACT;
				}
				if subset_mem(firstd->address, size1, secondu->address, size2) {
					return SUB;
				}
				if superset_mem(firstd->address, size1, secondu->address, size2) {
					return SUPER;
				}
				if ( overlap_mem(firstd->address, size1, secondu->address, size2) ||
						overlap_mem(secondu->address, size2, firstd->address, size1) ) {
					return OVERLAP;
				}

			}	
			if (firstd->operand->type == op_offset) {
				if (op_with_gs_seg(firstd->operand) && op_with_gs_seg(secondu->operand)) {
					if (firstd->operand->data.offset != secondu->operand->data.offset) {
						return 0;
					} else {
						return EXACT;
					}
				}
				assert(0);
			}
			break;

		case Base:
			if(firstd->operand->type != op_register){
					return 0;
			}

			// Base is always 32 bit register in x86
			if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.expression.base)) {
				return EXACT;

			}
			if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.expression.base)) {
				return SUB;
			}
			break;

		case Index:
			
			if(firstd->operand->type != op_register)
				return 0;

			// Base is always 32 bit register in x86
			if (exact_same_regs(firstd->operand->data.reg, secondu->operand->data.expression.index)) {
				return EXACT;
			}
			if (reg1_alias_reg2(firstd->operand->data.reg, secondu->operand->data.expression.index)) {
				return SUB;
			}
			break;

		default:
			
			break;
	}	
	return 0;
}


int compare_use_use(re_list_t *first, re_list_t *second) {
		
	use_node_t *firstu, *secondu;
	int type1, type2; 
	unsigned addr1, addr2, offset1, offset2; 
	size_t size1, size2;
	x86_reg_t *reg1, *reg2; 

	firstu = (use_node_t *)first->node;
	secondu = (use_node_t*)second->node; 
	reg1 = NULL;
	reg2 = NULL;

//process the first use
//use is an opd, then it could be anything
//use it as it is
	if(firstu->usetype == Opd){
				
		switch(firstu->operand->type){
			
			case op_expression:
				type1 = 0; 
				addr1 = firstu->address;
				size1 = translate_datatype_to_byte(firstu->operand->datatype);
				break;

			case op_register:
				type1 = 1; 
				reg1 = &firstu->operand->data.reg;
				break;
				
			case op_offset:
					
				if(op_with_gs_seg(firstu->operand)){
					type1 = 2; 
					offset1 = firstu->operand->data.offset; 
				}
				else
					type1 = 3;

				break;

			case op_immediate: 
				return 0;

			default: 
				assert(0);	
		}		
	}
	
	if(firstu->usetype == Base){
		type1 = 1; 
		reg1 = &firstu->operand->data.expression.base;
	}

	if(firstu->usetype == Index){
		type1 = 1; 
		reg1 = &firstu->operand->data.expression.index;
	}


	if(secondu->usetype == Opd){
				
		switch(secondu->operand->type){
			
			case op_expression:
				type2 = 0; 
				addr2 = secondu->address;
				size2 = translate_datatype_to_byte(secondu->operand->datatype);
				break;

			case op_register:
				type2 = 1; 
				reg2 = &secondu->operand->data.reg;
				break;
				
			case op_offset: 
				if(op_with_gs_seg(secondu->operand)){
					type2 = 2; 
					offset2 =  secondu->operand->data.offset; 
				}else
					type2 = 3;
				break;

			case op_immediate: 
				return 0;

			default: 
				assert(0);	

		}		
	}
	
	if(secondu->usetype == Base){
		type2 = 1; 
		reg2 = &secondu->operand->data.expression.base;
	}

	if(secondu->usetype == Index){
		type2 = 1; 
		reg2 = &secondu->operand->data.expression.index;
	}
	
	if(type1 != type2)
		return 0;

	switch(type1){

		case 0:
			if(!addr1 || !addr2)
				return 0;

			if exact_same_mem(addr1, size1, addr2, size2) 
				return EXACT;

			if subset_mem(addr1, size1, addr2, size2)
				return SUB;

			if superset_mem(addr1, size1, addr2, size2)			
				return SUPER;

			if (overlap_mem(addr1, size1, addr2, size2) || overlap_mem(addr2, size2, addr1, size1) )
				return OVERLAP;

			return 0;

		case 1:
			assert(reg1 && reg2);

			if (exact_same_regs((*reg1), (*reg2))) {
				return EXACT;
			}

			if (reg1_alias_reg2((*reg1), (*reg2))) {
				return SUB; 
			}

			if (reg1_alias_reg2((*reg2), (*reg1))) {
				return SUPER; 
			}

			if (same_alias((*reg1), (*reg2))) {

				if ((*reg1).size == (*reg2).size) {
					return 0;
				}

				if ((*reg1).size > (*reg2).size) {
					return SUPER;
				}

				return SUB;					
			}
			break;

		case 2:
			return offset1 == offset2 ? EXACT : 0;

		case 3:
			return 0;

		default:
			assert(0);
	}
		
	return 0;
}


int compare_two_targets(re_list_t* first, re_list_t * second){

	def_node_t *firstd, *secondd; 
	use_node_t *firstu, *secondu;

	int type; 


	if(first->node_type == DefNode 
			&& second ->node_type == DefNode){
		return compare_def_def(first, second);
	}	

	if(first->node_type == DefNode 
			&& second ->node_type == UseNode){

		return compare_def_use(first, second);
	}	

	if(first->node_type == UseNode 
			&& second ->node_type == DefNode){
		
		type = compare_def_use(second, first);

		switch(type){

			case 0:
			     return 0;

			case EXACT:
			case OVERLAP:
				return type; 

			case SUB: 
				return SUPER;

			case SUPER:
				return SUB;		
							
			default: 
				assert(0);
		}



	}	

	if(first->node_type == UseNode 
			&& second ->node_type == UseNode){
		return compare_use_use(first, second);
	}	
	return 0;
}


bool ok_to_get_value(re_list_t *entry) {
	def_node_t *defnode = NULL;
	use_node_t *usenode = NULL;
	if (entry->node_type == DefNode) {
		defnode = CAST2_DEF(entry->node);
		
		return (!((defnode->operand->type == op_expression) && 
			(defnode->address == 0)));
	}
	if (entry->node_type == UseNode) {

		usenode = CAST2_USE(entry->node);
		if (usenode->usetype != Opd) {
			return true;
		}
		return (!((usenode->operand->type == op_expression) && 
			(usenode->address == 0)));
	}
}

re_list_t * find_next_use_of_use(re_list_t* use, int *type){

	re_list_t *entry;

	list_for_each_entry(entry, &use->list, list) {
	
		if (entry == &re_ds.head) break;
		if (entry->node_type != UseNode)
			continue;
		
		*type = compare_two_targets(entry, use);

		if (*type) {
			return entry;
		}
	}
	return NULL;
}

re_list_t * find_next_def_of_use(re_list_t* use, int *type){

	re_list_t *entry;

	list_for_each_entry(entry, &use->list, list) {
	
		if (entry == &re_ds.head) break;
		if (entry->node_type != DefNode)
			continue;
		
		*type = compare_two_targets(entry, use);

		if (*type) {
			return entry;
		}
	}
	return NULL;
}

re_list_t * find_prev_use_of_use(re_list_t* use, int *type){

	re_list_t *entry;

	list_for_each_entry_reverse(entry, &use->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type != UseNode)
			continue;

		*type = compare_two_targets(entry, use);

		if (*type) return entry;
	}
	return NULL;
}

re_list_t * find_prev_def_of_use(re_list_t* use, int *type){

	re_list_t *entry;

	list_for_each_entry_reverse(entry, &use->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type != DefNode)
			continue;

		*type = compare_two_targets(entry, use);

		if (*type) return entry;
	}
	return NULL;
}

re_list_t * find_inst_of_node(re_list_t *node) {
	re_list_t *entry;
	list_for_each_entry(entry, &node->list, list) {
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) 
			return entry;
	}
	return NULL;
}

bool check_node_in_list(re_list_t *node, re_list_t *list) {
	re_list_t *temp;
	switch (node->node_type) {
	case InstNode:
		list_for_each_entry(temp, &list->instlist, instlist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	case UseNode:
		list_for_each_entry(temp, &list->uselist, uselist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	case DefNode:
		list_for_each_entry(temp, &list->deflist, deflist) {
			if (temp == node) {
				return true;
			}
		}
		break;
	}
	return false;
}


void re_resolve(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist) {


	while(RE_RES(re_deflist, re_uselist, re_instlist)){

		//LOG(stdout, "Start of one iteration of resolving\n");

		if (!(list_empty(&re_uselist->uselist))) {
			// only affect deflist one time
			resolve_use(re_deflist, re_uselist, re_instlist);
		}
		
		if (!(list_empty(&re_deflist->deflist))) {
			// affect deflist and instlist one time
			resolve_define(re_deflist, re_uselist, re_instlist);
		}

		if (!(list_empty(&re_instlist->instlist))) {
			// affect deflist and uselist one time
			resolve_inst(re_deflist, re_uselist, re_instlist);

		}

	}
}

void resolve_heuristics(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	
	int index; 
	x86_insn_t * inst; 	

	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index; 
	
	index = insttype_to_index(inst->type);

	if(index >= 0){
		post_resolve_heuristics[index](instnode, re_deflist, re_uselist, re_instlist);
	}
}

void resolve_use(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	int type;
	re_list_t *entry, *temp;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse, *inst;
	valset_u vt; 
	int offset; 
	int valoffset; 


	list_for_each_entry_safe_reverse(entry, temp, &re_uselist->uselist, uselist){

		assert(CAST2_USE(entry->node)->val_known);
#ifdef WITH_SOLVER
		adjust_use_constraint(entry);
#endif
		//deal with lea instruction in particular; 
		if(node_is_exp(entry, true) && !ok_to_check_alias(entry))
			goto out; 

		if(inst = find_inst_of_node(entry)){
			if (!check_inst_resolution(inst))
				add_to_instlist(inst, re_instlist);
		}

		assert(inst);

		if(entry->id == 53031)
			printf("target hit\n");



//be careful if the nextdef and entry have different addresses
		nextdef = find_next_def_of_use(entry, &type);

		//no nextdef, goto nextuse
		if(!nextdef)
			goto nextuse; 

		//nextdef has a super size
		if(type != EXACT && type !=SUB)
			goto nextuse;

//nextdef is an expression 
//then we need to exclude any possible unknown memory write inbetween
		if(node_is_exp(entry, true)){

			int memsize; 
			int index; 

			//get size of the nextdef
			memsize = translate_datatype_to_byte(CAST2_DEF(nextdef->node)->operand->datatype);

			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//in this case, the alias check is based on entry; 
				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_DEF(nextdef->node)->address- CAST2_USE(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextdef, entry))
					goto nextuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(nextdef->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);

		}else{
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
			//adjust the valset offset
			//to take care of ah, bh, ch, dh
			valoffset = adjust_val_offset(nextdef, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}


		if(!(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)){
			assign_def_before_value(nextdef, vt);
			add_to_deflist(nextdef, re_deflist);
		}else
			assert_val(nextdef, vt, true);

		//assign to the next use
nextuse:
		nextuse = find_next_use_of_use(entry, &type);

		if(!nextuse)
			goto prevdef; 

		//between the next use, there is a define	
		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto prevdef; 

		if(type != EXACT && type != SUB)
			goto prevdef;

		if(node_is_exp(entry, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(nextuse->node)->operand->datatype);

			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_USE(nextuse->node)->address- CAST2_USE(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextuse, entry))
					goto prevdef;

			}

			offset = CAST2_USE(nextuse->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);

		}else{
			//still have a problem here
			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));
			valoffset = adjust_val_offset(nextuse, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}

		//assign the value to the next use
		if(!(CAST2_USE(nextuse->node)->val_known)){
			assign_use_value(nextuse, vt);
			add_to_uselist(nextuse, re_uselist);

		}else{ assert_val(nextuse, vt,false); }

		//assign to the previous define 
prevdef:
		prevdef = find_prev_def_of_use(entry, &type);

		if(!prevdef)
			goto prevuse; 

		if(type != EXACT && type != SUB)
			goto prevuse;

		if(node_is_exp(entry, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(prevdef->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = index; 

//at this time, the base for alias check is the previous define 
				if(obstacle_between_two_targets(&re_ds.head, entry, prevdef))
					goto prevuse;
			}

			offset = CAST2_DEF(prevdef->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);
		}else{

			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));

			valoffset = adjust_val_offset(prevdef, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}

		if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
			assign_def_after_value(prevdef, vt);
			add_to_deflist(prevdef, re_deflist);

		}else{assert_val(prevdef, vt, false); }

		//assign to the previous use
prevuse:
		prevuse = find_prev_use_of_use(entry, &type);

		if(!prevuse)
			goto out; 

		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out; 

		if(type != EXACT && type != SUB)
			goto out;

		if(node_is_exp(entry, true)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(prevuse->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevuse))
					goto out;
			}

			offset = CAST2_USE(prevuse->node)->address - CAST2_USE(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_USE(entry->node)->val) + offset, sizeof(valset_u) - offset);
		}else{

			memcpy(&vt, (void*)&CAST2_USE(entry->node)->val, sizeof(valset_u));

			valoffset = adjust_val_offset(prevuse, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}
		if(!(CAST2_USE(prevuse->node)->val_known)){
			assign_use_value(prevuse, vt);
			add_to_uselist(prevuse, re_uselist);

		}else{assert_val(prevuse, vt, false);}
out:
		list_del(&entry->uselist);
	}
}

void resolve_define(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist){
	int type;
	re_list_t *entry, *temp;
	re_list_t *nextdef, *nextuse, *prevdef, *prevuse, *inst;
	valset_u vt; 
	int offset; 
	int valoffset;

	list_for_each_entry_safe_reverse(entry, temp, &re_deflist->deflist, deflist){

		assert(CAST2_DEF(entry->node)->val_stat & BeforeKnown
			|| CAST2_DEF(entry->node)->val_stat & AfterKnown);


		//we do not real with eip here, as we know every eip value
		if(CAST2_DEF(entry->node)->operand->type == op_register 
			&& CAST2_DEF(entry->node)->operand->data.reg.id == get_eip_id())
			goto out;  

#ifdef WITH_SOLVER
		adjust_def_constraint(entry);
#endif

		if(inst = find_inst_of_node(entry)){
			if (!check_inst_resolution(inst))
				add_to_instlist(inst, re_instlist);
		}



		if(entry->id == 71498)
			printf("The interesting point is hit\n");

		assert(inst);

		if( !(CAST2_DEF(entry->node)->val_stat & AfterKnown) )
			goto prevdef; 

		nextdef = find_next_def_of_def(entry, &type);

		if(!nextdef)
			goto nextuse; 

		//nextdef has a super size
		if(type != EXACT && type !=SUB)
			goto nextuse;

		//nextdef is an expression 
		if(node_is_exp(entry, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(nextdef->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_DEF(nextdef->node)->address- CAST2_DEF(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextdef, entry))
					goto nextuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(nextdef->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->afterval) + offset, sizeof(valset_u) - offset);

		}else{
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->afterval, sizeof(valset_u));
			valoffset = adjust_val_offset(nextdef, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);

		}


		if(!(CAST2_DEF(nextdef->node)->val_stat & BeforeKnown)){
			assign_def_before_value(nextdef, vt);
			add_to_deflist(nextdef, re_deflist);

		}else{
			assert_val(nextdef, vt, true);
		}

//assign to the next use
nextuse:
		nextuse = find_next_use_of_def(entry, &type);

		if(!nextuse)
			goto prevdef; 
	
		//between the next use, there is a define	
		if(nextdef && node1_add_before_node2(nextuse, nextdef))
			goto prevdef; 

		//there is unknown memory write between the current use 
		//and the next use

		if(type != EXACT && type !=SUB)
			goto prevdef;

		//nextdef is an expression 
		if(node_is_exp(entry, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(nextuse->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset = CAST2_USE(nextuse->node)->address- CAST2_DEF(entry->node)->address + index; 

				if(obstacle_between_two_targets(&re_ds.head, nextuse, entry))
					goto prevdef;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_USE(nextuse->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->afterval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->afterval, sizeof(valset_u));
			valoffset = adjust_val_offset(nextuse, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}

		//assign the value to the next use
			if(!(CAST2_USE(nextuse->node)->val_known)){
				assign_use_value(nextuse, vt);
				add_to_uselist(nextuse, re_uselist);
			}else{assert_val(nextuse, vt,false);}

//assign to the previous define 
prevdef:
		if( !(CAST2_DEF(entry->node)->val_stat & BeforeKnown) )
			goto out; 

		prevdef = find_prev_def_of_def(entry, &type);

		if(!prevdef)
			goto prevuse; 


		if(type != EXACT && type !=SUB)
			goto prevuse;

		//nextdef is an expression 
		if(node_is_exp(entry, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_DEF(prevdef->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset =  index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevdef))
					goto prevuse;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_DEF(prevdef->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->beforeval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->beforeval, sizeof(valset_u));
			valoffset = adjust_val_offset(prevdef, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}

			if(!(CAST2_DEF(prevdef->node)->val_stat & AfterKnown)){
				assign_def_after_value(prevdef, vt);
				add_to_deflist(prevdef, re_deflist);

			}else{assert_val(prevdef, vt, false); }

//assign to the previous use
prevuse:
		prevuse = find_prev_use_of_def(entry, &type);

		if(!prevuse)
			goto out; 
		
		if(prevdef && node1_add_before_node2(prevdef, prevuse))
			goto out; 

		if(type != EXACT && type !=SUB)
			goto out;

		//nextdef is an expression 
		if(node_is_exp(entry, false)){

			int memsize; 
			int index; 

			//get size of the next def
			memsize = translate_datatype_to_byte(CAST2_USE(prevuse->node)->operand->datatype);
			//check unknown memory write between each overlap byte
			for(index = 0; index < memsize; index++){

				//set up the offset for alias check 
				re_ds.alias_offset =  index; 

				if(obstacle_between_two_targets(&re_ds.head, entry, prevuse))
					goto out;
			}

			//considering about the offset between two addresses; 
			offset = CAST2_USE(prevuse->node)->address - CAST2_DEF(entry->node)->address; 
			memcpy(&vt, ((void*)&CAST2_DEF(entry->node)->beforeval) + offset, sizeof(valset_u) - offset);

		}else{

			//still have a problem here
			memcpy(&vt, (void*)&CAST2_DEF(entry->node)->beforeval, sizeof(valset_u));
			valoffset = adjust_val_offset(prevuse, type);
			memcpy(&vt, ((void*)(&vt)) + valoffset, sizeof(valset_u) - valoffset);
		}

			if(!(CAST2_USE(prevuse->node)->val_known)){
				assign_use_value(prevuse,vt);
				add_to_uselist(prevuse, re_uselist);

			}else{assert_val(prevuse, vt, false); }

out:
		list_del(&entry->deflist);
	}
}


int insttype_to_index(enum x86_insn_type type){

	int index; 
	for(index = 0; index < ninst; index++){
		
		if(opcode_index_tab[index].type == type){
			return index; 
		}
	}

	return -1;
}


static bool use_after_def(re_list_t *use, int regid, re_list_t *def[], int ndef){

	int defindex;
	x86_insn_t* x86inst; 
	re_list_t* inst;

	inst = find_inst_of_node(use);
	x86inst = &re_ds.instlist[CAST2_INST(inst->node)->inst_index];

	if(x86inst->type == insn_leave)
		return true;

	for(defindex = 0; defindex < ndef; defindex++){
		//this defines a register and its ID matches the register for use
		if(CAST2_DEF(def[defindex]->node)->operand->type == op_register && CAST2_DEF(def[defindex]->node)->operand->data.reg.id == regid){
			//this use has been redefined, so we cannot check
			if(use->id < def[defindex]->id)
				return true;
		}	
	}
	return false; 
}

void correctness_check(re_list_t * instnode){

	inst_node_t *inst; 
	re_list_t *use[NOPD], *def[NOPD];
	operand_val_t *regvals; 
	use_node_t * tempuse; 
	def_node_t * tempdef;

	size_t nuse, ndef; 
	int i,j, regindex; 

	//get the operands log from re_ds	
	inst = (inst_node_t*)(instnode->node); 
	regvals = &re_ds.oplog_list.opval_list[inst->inst_index];

	if(regvals -> regnum == 0)
		return; 
	
	obtain_inst_elements(instnode, use, def, &nuse, &ndef);

	//check every use	
	//we can only check the values of registers
	for(i = 0; i < nuse; i++ ){

		tempuse = CAST2_USE(use[i]->node);		

		if(!tempuse->val_known)
			continue; 

		if(tempuse->usetype == Base ){
			for(regindex = 0; regindex < regvals->regnum; regindex++){

				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->data.expression.base.id, def, ndef))
					continue; 

				//for debug use
				if(tempuse->operand->data.expression.base.id == get_esp_id()){
					if(tempuse->val.dword == regvals->regs[regindex].val.dword || tempuse->val.dword == regvals->regs[regindex].val.dword - 0x4)
						continue;
				}				
				//end debugging use;


				if(tempuse->operand->data.expression.base.id == regvals->regs[regindex].reg_num)
					assert_val(use[i], regvals->regs[regindex].val, false);
			}			
		}	
	
		if(tempuse->usetype == Index){
			for(regindex = 0; regindex < regvals->regnum; regindex++){
	
				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->data.expression.index.id, def, ndef))
					continue; 


                                if(tempuse->operand->data.expression.index.id == regvals->regs[regindex].reg_num)
                                        assert_val(use[i], regvals->regs[regindex].val, false);
                        }
		}

		if(tempuse->usetype == Opd && tempuse->operand->type == op_register){

			for(regindex = 0; regindex < regvals->regnum; regindex++){
				
				//if this use has been redefined, we do not consider about it
				if(use_after_def(use[i], tempuse->operand->data.reg.id, def, ndef))
					continue; 

                                if(tempuse->operand->data.reg.id == regvals->regs[regindex].reg_num)
                                        assert_val(use[i], regvals->regs[regindex].val, false);
                        }
		}
	}
	
	//check before value of def
	for(j = 0; j < ndef; j++){
		tempdef = CAST2_DEF(def[j]->node);

		if(tempdef->operand->type == op_register && (tempdef->val_stat & BeforeKnown)){
			for(regindex = 0; regindex < regvals->regnum; regindex++){
				if(use_after_def(def[j], tempdef->operand->data.reg.id, def, ndef))
					continue; 			

                                if(tempdef->operand->data.reg.id == regvals->regs[regindex].reg_num)
                                        assert_val(def[j], regvals->regs[regindex].val, true);
			}
		}
	}
}
	

void resolve_inst(re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist) {
/* list_for_each_entry (instlist)
 * 	Search all the operands of each instruction
 * 	justify whether those known operands meet the requirement of constraints
 *	According to instruction semantics, resolve define/use  and add them to the corresponding list
 */
	int index; 
	x86_insn_t * inst; 	
	re_list_t *entry, *temp;

	list_for_each_entry_safe_reverse(entry, temp, &re_instlist->instlist, instlist){

		inst = re_ds.instlist + CAST2_INST(entry->node)->inst_index; 
		index = insttype_to_index(inst->type);
		
		if(index >= 0){
			inst_resolver[index](entry, re_deflist, re_uselist);
		}
		else{
			assert(0);
		}

		list_del(&entry->instlist);

#ifdef DATA_LOGGED
	//check the resolved values against the ground truth log
	//to aid the debugging process
	//do not perform correctness check when verifying alias
		if(re_ds.rec_count == 0 && re_ds.oplog_list.log_num > 0)
			correctness_check(entry);	
#endif
	}
}


#ifdef FIX_OPTM

void fix_optimization(re_list_t* inst){
	
	re_list_t *dst[NOPD], *src[NOPD];
        int nuse, ndef;
        int it;
        def_node_t *def;
        use_node_t *use;
	re_list_t re_deflist, re_uselist, re_instlist;  	

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	

        //get the operands of the instruciton   
        obtain_inst_operand(inst, src, dst, &nuse, &ndef);		

	for(it = 0; it < nuse; it++){
		if(CAST2_USE(src[it]->node)->val_known)
			add_to_uselist(src[it], &re_uselist);
	}

	for(it = 0; it < ndef; it++){
		if(CAST2_DEF(dst[it]->node)->val_stat & AfterKnown)
			add_to_deflist(dst[it], &re_deflist);
	}

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
}
	

#endif




int check_inst_resolution(re_list_t* inst){

	re_list_t *entry;

	list_for_each_entry_reverse(entry, &inst->list, list) {

		if (entry == &re_ds.head) return 1;	

		if(entry->node_type == InstNode) return 1; 

		if (entry->node_type == DefNode){
			if(! (CAST2_DEF(entry->node)->val_stat & AfterKnown))
				return 0;

			if( CAST2_DEF(entry->node)->operand->type == op_expression 
				&& !CAST2_DEF(entry->node)->address)
					return 0;

//			if(CAST2_DEF(entry->node)->val_stat != (BeforeKnown | AfterKnown))
//				return 0;
		}

		if(entry->node_type == UseNode){

			if(!CAST2_USE(entry->node)->val_known)
				return 0;

			if(CAST2_USE(entry->node)->usetype == Opd 
				&& CAST2_USE(entry->node)->operand->type == op_expression)					
				if(!CAST2_USE(entry->node)->address)
					return 0;
		}
	}
	return 1;
}


void res_expression(re_list_t * exp, re_list_t *uselist){

	re_list_t *index, *base, *entry; 
	x86_op_t* opd;
	unsigned baseaddr, indexaddr;

	index = NULL;
	base = NULL;
	baseaddr = 0; 
	indexaddr = 0;

	opd = (exp->node_type == DefNode ? CAST2_DEF(exp->node)->operand : CAST2_USE(exp->node)->operand);

	get_element_of_exp(exp, &index, &base);
	
	switch (exp_addr_status(base, index)) {
		case KBaseKIndex:
			if (base){
				baseaddr = CAST2_USE(base->node)->val.dword;
			}

			if (index) {
				indexaddr = CAST2_USE(index->node)->val.dword;
			}
			break;

		case UBase:
		case UIndex:

			if(exp->node_type == DefNode) {
				add_to_umemlist(exp);
			}
			return;

		case KBaseUIndex:
			if (exp->node_type == DefNode) {
				if (!CAST2_DEF(exp->node)->address){
					add_to_umemlist(exp);
				} else {
					baseaddr = CAST2_USE(base->node)->val.dword;
					unsigned temp = CAST2_DEF(exp->node)->address - baseaddr -
							(int)(opd->data.expression.disp);
					indexaddr = temp/(opd->data.expression.scale);
					valset_u vt;
					vt.dword = indexaddr;
					assign_use_value(index, vt);
					add_to_uselist(index, uselist);
				}
			}
			return;
			break;
		case UBaseKIndex:
			if (exp->node_type == DefNode) {
				if (!CAST2_DEF(exp->node)->address) {
					add_to_umemlist(exp);
				} else {
					indexaddr = CAST2_USE(index->node)->val.dword;
					baseaddr = CAST2_DEF(exp->node)->address -
						indexaddr * opd->data.expression.scale -
						(int)(opd->data.expression.disp);
					valset_u vt;
					vt.dword = baseaddr;
					assign_use_value(base, vt);
					add_to_uselist(base, uselist);
				}
			}
			return;
			break;
		case UBaseUIndex:
			if((exp->node_type == DefNode) && (!CAST2_DEF(exp->node)->address)){
				add_to_umemlist(exp);
			}
			return;
			break;
		case NBaseNIndex:
			break;
		default:
			assert(0);
			break;
	}

	if(exp->node_type == DefNode){
		re_list_t *nextdef; 
		int type;
		valset_u rv;

		CAST2_DEF(exp->node)->address = baseaddr + indexaddr * opd->data.expression.scale +  (int)(opd->data.expression.disp);

		if (op_with_gs_seg(CAST2_DEF(exp->node)->operand)) {
			CAST2_DEF(exp->node)->address += re_ds.coredata->corereg.gs_base;
		}

		remove_from_umemlist(exp);



		if(assign_def_before_mem_val(exp, &rv, uselist)){
			if(!(CAST2_DEF(exp->node)->val_stat & BeforeKnown)){
				assign_def_before_value(exp, rv);
			}else{
				assert_val(exp, rv, true);
			}
		}

		if(assign_def_after_mem_val(exp, &rv, uselist)){
			if(!(CAST2_DEF(exp->node)->val_stat & AfterKnown)){
				assign_def_after_value(exp, rv);
			}else{
				assert_val(exp, rv, false);
			}
		}

	}

	if(exp->node_type == UseNode){
		re_list_t *nextdef;	
		int type;
		valset_u rv;

		CAST2_USE(exp->node)->address = baseaddr + 
		    indexaddr * opd->data.expression.scale + 
		    (int)(opd->data.expression.disp);


		if (op_with_gs_seg(CAST2_USE(exp->node)->operand)) {
			CAST2_USE(exp->node)->address += re_ds.coredata->corereg.gs_base;
		}

		//take care of lea instruction particularly
		if(!ok_to_check_alias(exp))
			return; 

		if(assign_use_mem_val(exp, &rv, uselist)){
			if(!CAST2_USE(exp->node)->val_known){
				assign_use_value(exp, rv);
			}else{
				assert_val(exp, rv, false);
			}
		}
	}	
}

bool node_is_exp(re_list_t* node, bool use){
	if(use)
		return CAST2_USE(node->node)->usetype == Opd && CAST2_USE(node->node)->operand->type == op_expression ? 1 : 0;

	return CAST2_DEF(node->node)->operand->type == op_expression ? 1 : 0;
}


bool address_is_known(re_list_t *node) {
	switch (node->node_type) {
		case UseNode:
			return CAST2_USE(node->node)->address != 0 ? true : false;
			break;
		case DefNode:
			return CAST2_DEF(node->node)->address != 0 ? true : false;
			break;
		default:
			assert(0);
			break;
	}
}

//find all the operands use after a def node
void get_src_of_def(re_list_t* def, re_list_t **use, int *nuse){

	re_list_t * entry;
	re_list_t * inst; 


	x86_insn_t* x86inst; 

	*nuse = 0;

	inst = find_inst_of_node(def);

	x86inst = &re_ds.instlist[CAST2_INST(inst->node)->inst_index];


	list_for_each_entry_reverse(entry, &def->list, list){

		if(entry->node_type != UseNode)
			return; 

		if(CAST2_USE(entry->node)->usetype == Opd || (strcmp(x86inst->mnemonic, "lea") == 0) ){
			use[(*nuse)++] = entry; 
		}
	}
}

//only to get the operands of an instruction
void obtain_inst_elements(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	re_list_t* entry;

	*nuse = 0;
	*ndef = 0;

	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) break;

		if(entry->node_type == UseNode){
			use[(*nuse)++] = entry;
		}
		
		if(entry->node_type == DefNode){
			def[(*ndef)++] = entry;
		}
	}
}

//only to get the operands of an instruction
void obtain_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	re_list_t* entry;

	*nuse = 0;
	*ndef = 0;

	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) break;

		if(entry->node_type == UseNode){
			if(CAST2_USE(entry->node)->usetype == Opd)
				use[(*nuse)++] = entry;
		}
		
		if(entry->node_type == DefNode){
			def[(*ndef)++] = entry;
		}
	}
}

void traverse_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, re_list_t* uselist, re_list_t* deflist, int *nuse, int *ndef){
		
	bool tak, addr, tak1, addr1;
	re_list_t* entry;

	*nuse = 0;
	*ndef = 0;

	list_for_each_entry_reverse(entry, &inst->list, list){
		if(entry == &re_ds.head) break;
		if(entry->node_type == InstNode) break;

		if(entry->node_type == UseNode){
			if(node_is_exp(entry, true)){ 
				tak = CAST2_USE(entry->node)->val_known;
				addr = CAST2_USE(entry->node)->address;

				if(!tak || !addr){
					res_expression(entry, uselist);
					tak1 = CAST2_USE(entry->node)->val_known;
					addr1 = CAST2_USE(entry->node)->address;

					if( (tak != tak1 || addr != addr1) && addr1 && tak1)
						add_to_uselist(entry, uselist);
				}

			}
			if(CAST2_USE(entry->node)->usetype == Opd)
				use[(*nuse)++] = entry;
		}
		
		if(entry->node_type == DefNode){
			if(node_is_exp(entry, false)){

				tak = CAST2_DEF(entry->node)->val_stat & AfterKnown;
				addr = CAST2_DEF(entry->node)->address;
				if(!tak || !addr){

					res_expression(entry, uselist);

					tak1 = CAST2_DEF(entry->node)->val_stat & AfterKnown;
					addr1 = CAST2_DEF(entry->node)->address;
					if( (tak != tak1 || addr != addr1) && addr1 && tak1)
						add_to_deflist(entry, deflist);
				}

			}

			def[(*ndef)++] = entry;

		}
	}

//if the unknown umem list is empty, should we do some clean up here?

}

void split_expression_to_use(x86_op_t* opd){


	re_list_t *base, *index;

#ifdef WITH_SOLVER
	re_list_t * exp; 
	valset_u tempval;
	Z3_ast baseast, indexast, scaleast, dispast; 

	exp = list_first_entry(&re_ds.head.list, re_list_t, list);
#endif

	base = NULL;
	index = NULL;

	switch (get_expreg_status(opd->data.expression)) {
		case No_Reg:
			break;
		case Base_Reg:
			 base = add_new_use(opd, Base);	
			break;
		case Index_Reg:
			index = add_new_use(opd, Index);	
			break;
		case Base_Index_Reg:
			base = add_new_use(opd, Base);	
			index = add_new_use(opd, Index);	
			break;
		default: 
			assert(0);
	}

#ifdef WITH_SOLVER

	if(base)
		baseast = CAST2_USE(base->node)->constraint;
	else{
		tempval.dword = 0;
		baseast = val_to_bv(tempval, sizeof(unsigned));
	}
	
	if(index){
		indexast = CAST2_USE(index->node)->constraint; 
	}else{
		tempval.dword = 0;
		indexast = val_to_bv(tempval, sizeof(unsigned));
	}

	tempval.dword = opd->data.expression.scale;
	scaleast = val_to_bv(tempval, sizeof(unsigned));

	tempval.dword = opd->data.expression.disp;
	dispast = val_to_bv(tempval, sizeof(unsigned));

	if(exp->node_type == UseNode){
		CAST2_USE(exp->node)->addresscst = Z3_mk_bvadd(re_ds.zctx, Z3_mk_bvadd(re_ds.zctx, baseast, Z3_mk_bvmul(re_ds.zctx, indexast, scaleast)), dispast);
	}else{
		CAST2_DEF(exp->node)->addresscst = Z3_mk_bvadd(re_ds.zctx, Z3_mk_bvadd(re_ds.zctx, baseast, Z3_mk_bvmul(re_ds.zctx, indexast, scaleast)), dispast);
	}
	
#endif
}


bool node1_add_before_node2(re_list_t *node1, re_list_t* node2){
	return node1->id < node2->id ? true : false;
}


void destroy_corelist() {
	delete_corelist(&re_ds.head);
}


void add_to_deflist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->deflist, &listhead->deflist);
}


void add_to_uselist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->uselist, &listhead->uselist);
}


void add_to_instlist(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add(&entry->instlist, &listhead->instlist);
}


void add_to_instlist_tail(re_list_t *entry, re_list_t *listhead) {
       if (!check_node_in_list(entry, listhead))
               list_add_tail(&entry->instlist, &listhead->instlist);
}


void remove_from_deflist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->deflist);
       }
}


void remove_from_uselist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->uselist);
       }
}


void remove_from_instlist(re_list_t *entry, re_list_t *listhead) {
       if (check_node_in_list(entry, listhead)) {
               list_del(&entry->instlist);
       }
}

void zero_valset(valset_u *vt) {
	memset(vt, 0, sizeof(valset_u));
}

void one_valset(valset_u *vt) {
	memset(vt, 0xff, sizeof(valset_u));
}

void clean_valset(valset_u *vt, enum x86_op_datatype datatype, bool sign) {
	unsigned char tchar;
	unsigned short tshort;
	unsigned long tlong;
	switch (datatype) {
		case op_byte:
			tchar = vt->byte;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->byte = tchar;
			break;
		case op_word:
			tshort = vt->word;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->word = tshort;
			break;
		case op_dword:
			tlong = vt->dword;
			if (sign) {
				one_valset(vt);
			} else {
				zero_valset(vt);
			}
			vt->dword = tlong;
			break;
		case op_dqword:
			break;
		default:
			assert(0);
			break;
	}
}


bool sign_of_valset(valset_u *vt, enum x86_op_datatype datatype) {
	bool sign;
	
	switch (datatype) {
		case op_byte:
			sign = vt->byte & (1 << (BYTE_SIZE - 1));
			break;
		case op_word:
			sign = vt->word & (1 << (WORD_SIZE - 1));
			break;
		case op_dword:
			sign = vt->dword & (1 << (DWORD_SIZE - 1));
			break;
		default:
			LOG(stdout, "%d\n", datatype);
			assert(0);
			break;
	}
	return sign;
}


void sign_extend_valset(valset_u *vt, enum x86_op_datatype datatype) {
	bool sign;

	sign = sign_of_valset(vt, datatype);

	clean_valset(vt, datatype, sign);
}


re_list_t * get_entry_by_id(unsigned id) {
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if (entry->id == id) {
			return entry;
		}
	}
	return NULL;
}


re_list_t *get_entry_by_inst_id(unsigned inst_index) {
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {
		if ((entry->node_type == InstNode) && 
			(CAST2_INST(entry->node)->inst_index == inst_index)) {
			return entry;
		}
	}
	return NULL;
}
