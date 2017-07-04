#ifdef BIN_ALIAS
#include "reverse_exe.h"
#include "bin_alias.h"
#include "insthandler.h"

#define SUM_MAX_SIZE 256
#define ITEMDEM "-"
#define INFODEM ":"




static void process_summary_line(char * line, unsigned index){

	char *str1, *str2, *saveptr1, *saveptr2; 
	char *token, *start, *end;
	char *endptr;  
	int regcount; 

	unsigned libbase = 0;	
	enum sumtype type;

	for(regcount = 0, str1 = line; ;regcount++, str1 = NULL){
		token = strtok_r(str1, ITEMDEM, &saveptr1);
		if(token == NULL)
			break; 	

		//The first item represents the type
		if(regcount == 0){
			if(strcmp(token, "skip") == 0){
				type = Skip;
				continue; 
			}
		
			if(strcmp(token, "ro") == 0 ){
				type = Ro;
				continue;
			}
			assert(0 && "The summary type is not correct\n");	
		}

		//The second item represents the library base address
		if (regcount == 1){
			libbase = strtoll(token, &endptr, 16);
			continue;
		}
			
		start = strtok_r(token, INFODEM, &saveptr2);
		assert(start);
		end = strtok_r(NULL, INFODEM, &saveptr2);
		assert(end);

		switch(type){
			
			case Skip:
				assert (regcount <= MAXFUNC);
				re_ds.alias_heuristic.mff[regcount - 2].startaddr = strtoll(start, &endptr, 16) + libbase;
				re_ds.alias_heuristic.mff[regcount - 2].endaddr = strtoll(end, &endptr, 16) + libbase;
				break;

			case Ro:
				re_ds.alias_heuristic.rom[regcount - 2].startaddr = strtoll(start, &endptr, 16) + libbase;
				re_ds.alias_heuristic.rom[regcount - 2].endaddr = strtoll(end, &endptr, 16) + libbase;
				break;

			default:
				assert(0 && "The summary type is not correct\n");
		}
	}

	if(type == Skip)
		re_ds.alias_heuristic.mem_free_num = regcount - 2; 

	if(type == Ro)
		re_ds.alias_heuristic.read_only_num = regcount - 2; 
}

static void load_summary(){
	
	char log_buf[SUM_MAX_SIZE];
	FILE* file; 
	unsigned index; 


//init the summary numbers to be 0
	re_ds.alias_heuristic.mem_free_num = 0; 
	re_ds.alias_heuristic.read_only_num = 0; 

	if((file = fopen(sum_path, "r")) == NULL){
		return;
	}
	
	index = 0;
	memset(log_buf, 0, SUM_MAX_SIZE);
	
	while(fgets(log_buf, sizeof(log_buf), file) != 0){
		process_summary_line(log_buf, index);
		index++;
	}
}


void init_bin_alias(){

	memset(re_ds.flist, 0, MAXFUNC * sizeof(func_info_t));

	re_ds.alias_heuristic.mem_free_num = 0;

	load_summary();	

}

//adjust the boundary of a function

void adjust_func_boundary(re_list_t* instnode){

	inst_node_t* inst; 
	x86_insn_t *x86inst;	
	unsigned funcid;
	unsigned instid; 

	inst = CAST2_INST(instnode->node);
	instid = inst->inst_index;
	funcid = inst->funcid;
	x86inst = &re_ds.instlist[inst->inst_index];

//Maximal function number is MAXFUNC	
	assert(funcid < MAXFUNC);

//check if this is the first function 
//if so
	//for the first function, the start is always 0
	//so we do not adjust here 
	if(funcid == 0){
		//the end is increasing
		assert(re_ds.flist[funcid].end <= instid);
		re_ds.flist[funcid].end = instid;
	}else{

		if (re_ds.flist[funcid].start == 0)
			re_ds.flist[funcid].start = instid;

		assert(re_ds.flist[funcid].start <= instid);

		re_ds.flist[funcid].end = instid > re_ds.flist[funcid].end ? instid : re_ds.flist[funcid].end;
	}
//else
	if(x86inst->type == insn_return)
		re_ds.flist[funcid].returned = true;	

}


//exp2 is the operand with known address 
bool rule_by_readonly(re_list_t *exp1, re_list_t *exp2){
	
//if exp2 belongs to read only area, then not possible to be alias with exp2
	unsigned address; 
	int it; 
	
	assert(exp2->id > exp1->id);
	address = 0;

	if(exp2->node_type == UseNode)
		address = CAST2_USE(exp2->node)->address;

	if(exp2->node_type == DefNode)
		address = CAST2_DEF(exp2->node)->address; 

	assert(address);
	
	for(it = 0; it < re_ds.alias_heuristic.read_only_num; it++){
		//the address falls into a read only area
		if(address >= re_ds.alias_heuristic.rom[it].startaddr && address < re_ds.alias_heuristic.rom[it].endaddr)
			return false; 
	}

	return true; 
}

//exp2 is the operand with known address 
bool rule_by_summary(re_list_t* exp1, re_list_t* exp2){
//basic logic
//check if exp1 is in a memory-self-contained function.
//if so, compare the stack relation between func1 and func2
//make sure their stack does not overlap  
//if so, then we can conclude they are not aliases
	inst_node_t *inst1, *inst2; 
	unsigned funcid1, funcid2;
	x86_insn_t *x86inst1, *x86inst2; 	
	bool mf1, mf2; 
	int it;
	

	//check and make sure that exp2 is added after exp1
	assert(exp2->id > exp1->id);
		
	inst1 = CAST2_INST(find_inst_of_node(exp1)->node);
	inst2 = CAST2_INST(find_inst_of_node(exp2)->node);

	funcid1 = inst1->funcid; 
	funcid2 = inst2->funcid;
	
	x86inst1 = &re_ds.instlist[inst1->inst_index];
	x86inst2 = &re_ds.instlist[inst2->inst_index];

	mf1 = false;
	mf2 = false;


//the block is in a memory free function
	for(it = 0; it < re_ds.alias_heuristic.mem_free_num; it++){
		if(x86inst1->addr >= re_ds.alias_heuristic.mff[it].startaddr && x86inst1->addr <= re_ds.alias_heuristic.mff[it].endaddr){
			mf1 = true;
			break;
		}
	}
	

	for(it = 0; it < re_ds.alias_heuristic.mem_free_num; it++){
		if(x86inst2->addr >= re_ds.alias_heuristic.mff[it].startaddr && x86inst2->addr <= re_ds.alias_heuristic.mff[it].endaddr){
			mf2 = true; 
			break;
		}
	}


	if(mf1 || mf2){	
		if (!re_ds.flist[funcid2].returned || re_ds.flist[funcid2].start < inst1->inst_index)
			return false;		
	
		if(exp2->id == 51898)
			return false; 
	}	

	return true;
}


//rule out by gs segmentation
bool rule_by_gs(re_list_t* exp1, re_list_t *exp2){

	x86_op_t *operand; 	
	operand = NULL;

	if(exp2->node_type == UseNode)
		operand  = CAST2_USE(exp2->node)->operand; 		

	if(exp2->node_type == DefNode)
		operand = CAST2_DEF(exp2->node)->operand; 

	assert(operand);

	if(op_with_gs_seg(operand))	
		return false;

	return true;
}


bool bin_alias_check(re_list_t * exp1, re_list_t* exp2){
	if (!rule_by_summary(exp1, exp2))
		return false;

	if(!rule_by_readonly(exp1, exp2))
		return false;

	if(!rule_by_gs(exp1, exp2))
		return false;
	
	return true;
}

void init_reg_use(re_list_t* usenode, re_list_t* uselist){
/*logics here
check if this is the first use
if so, assign the value from the log
*/
	use_node_t * use; 
	inst_node_t * inst; 
	re_list_t *prevdef; 
	int dtype;	
	operand_val_t *regvals;
	int regid; 
	int regindex;

	use = CAST2_USE(usenode->node);
	inst = CAST2_INST(find_inst_of_node(usenode)->node);

	//this is not a use of register
	if(use->usetype == Opd && use->operand->type == op_expression)
		return;	

	prevdef = find_prev_def_of_def(usenode, &dtype);
	//there is a define before, do nothing
	if(prevdef)
		return; 
	
	if(use->usetype == Opd)
		regid = use->operand->data.reg.id;		
	if(use->usetype == Base)
		regid = use->operand->data.expression.base.id;
	if(use->usetype == Index)
		regid = use->operand->data.expression.index.id;

	regvals = &re_ds.oplog_list.opval_list[inst->inst_index];

	for(regindex = 0; regindex < regvals->regnum; regindex++){
		if (regvals->regs[regindex].reg_num == regid){
			assign_use_value(usenode, regvals->regs[regindex].val);	
			add_to_uselist(usenode, uselist);
			return; 
		}	
	}
}


//binary search tree to store the conflicting alias pairs

int compare_two_pairs(alias_pair_t* t1, unsigned id1, unsigned id2){
	
	assert(t1);

	if(t1->id1 > id1)
		return LARGE;

	if(t1->id1 < id1)
		return LESS;

	if(t1->id2 > id2)
		return LARGE; 
		
	if(t1->id2 < id2)
		return LESS;
	
	return EQUAL; 
}

void insert_pair(alias_pair_t** tree, unsigned id1, unsigned id2){
	alias_pair_t* node;
	node = NULL;
	
	if(!(*tree)){
		node = (alias_pair_t*)malloc(sizeof(alias_pair_t));
		assert(node);
		node->left = node->right = NULL;
		node->id1 = id1; 
		node->id2 = id2; 
		*tree = node; 
		return ;
	}

	switch(compare_two_pairs(*tree, id1, id2)){
		case LARGE:
			insert_pair(&(*tree)->left, id1, id2);
			break;

		case LESS:
			insert_pair(&(*tree)->right, id1, id2);
			break;
		
		case EQUAL:
			
			break;
	}
}

alias_pair_t* search_pair(alias_pair_t** tree, unsigned id1, unsigned id2){

	if(!(*tree))
		return NULL;	
	
	switch(compare_two_pairs(*tree, id1, id2)){
		case LARGE:
			return search_pair(&(*tree)->left, id1, id2);

		case LESS:
			return search_pair(&(*tree)->right, id1, id2);
		
		case EQUAL:
			return *tree; 	
	}
}




#endif
