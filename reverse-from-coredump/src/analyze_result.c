#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "reverse_exe.h"
#include "re_stackpointer.h"
#include "analyze_result.h"


int *inst_tainted; 
int taintpair;
int branch;

static x86_op_t* opd_from_reg(x86_reg_t * reg){

	x86_op_t * opd; 

	opd = (x86_op_t *)calloc(1, sizeof(x86_op_t));	
	opd->type = op_register; 
	opd->data.reg = *reg;
	opd->datatype = op_dword; 

	return opd; 
}

static void taint_operand(x86_op_t* opd){

	re_list_t node; 
	use_node_t use;
	re_list_t* prevdef; 
	int dtype; 

	re_list_t srclist; 
	re_list_t* entry, *temp;

	re_list_t* base, *index; 
	re_list_t *defsrc[NOPD];
	int nuse, i; 

//add the new node to the main list 
	node.node_type = UseNode; 
	memset(&use, 0, sizeof(use_node_t));
	use.operand = opd; 
	use.usetype = Opd; 
	node.node = &use; 
	list_add_tail(&node.list, &re_ds.head.list);

	INIT_LIST_HEAD(&srclist.uselist);	
	add_to_uselist(&node, &srclist);

	while(!list_empty(&srclist.uselist)){


		list_for_each_entry_safe_reverse(entry, temp, &srclist.uselist, uselist){
			fprintf(stdout, " ============= One pair of taint propagation\n");	

			if(entry != &node){
				print_instnode(find_inst_of_node(entry)->node);
				inst_tainted[CAST2_INST(find_inst_of_node(entry)->node)->inst_index] = 1;

	
				if(CAST2_INST(find_inst_of_node(entry)->node)->inst_index > 927) {
					branch++;
					goto endbranch;
				}
			}
			
			taintpair++;

			print_usenode(entry->node);
			prevdef = find_prev_def_of_use(entry, &dtype);

			if(prevdef){
					
				print_instnode(find_inst_of_node(prevdef)->node);
				
				print_defnode(prevdef->node);

				if(node_is_exp(prevdef, false)){
					base = NULL;
					index = NULL;
					get_element_of_exp(prevdef, &index, &base);
					if(base)
						add_to_uselist(base, &srclist);

					if(index)
						add_to_uselist(index, &srclist);
				}

				get_src_of_def(prevdef, defsrc, &nuse);

				for(i = 0; i < nuse; i++){
					if(CAST2_USE(defsrc[i]->node)->operand->type == op_register) 
						add_to_uselist(defsrc[i], &srclist);
	
					if(CAST2_USE(defsrc[i]->node)->operand->type == op_expression){ 

						add_to_uselist(defsrc[i], &srclist);
			
						x86_insn_t* x86inst; 
						x86inst = &re_ds.instlist[
							CAST2_INST(find_inst_of_node(defsrc[i])->node)->inst_index];

						if(strcmp(x86inst->mnemonic, "lea") == 0 )	
							continue;

						base = NULL;
						index = NULL;

						get_element_of_exp(defsrc[i], &index, &base);
						if(base)
							add_to_uselist(base, &srclist);

						if(index)
							add_to_uselist(index, &srclist);
					}
				}
			}		
			else{
				branch++;
			}

endbranch:

			list_del(&entry->uselist);
		
			fprintf(stdout, " ============= Finish one pair of taint propagation\n");	
		}
	}
	list_del(&node.list);		
}

static void taint_analysis(void){
	x86_reg_t *index, *base; 
	int taintsize;
	int i; 

	index = NULL;
	base = NULL;

	if(!re_ds.root)
		return; 

	base = re_ds.root->data.expression.base.id ? &re_ds.root->data.expression.base : NULL;

	index = re_ds.root->data.expression.index.id ? &re_ds.root->data.expression.index : NULL;

	if(base){
	
		printf("Base name is %s \n", base->name);

		taint_operand(opd_from_reg(base));
	}

	if(index){
		printf("Index name is %s \n", index->name);
	
		taint_operand(opd_from_reg(index));
	}

	taintsize = 0;
	
	for(i=0; i < re_ds.instnum; i++){
		taintsize += inst_tainted[i] ? 1 : 0;
	}	
	printf("======= The total number of tainted instruction is %d\n", taintsize);
	printf("======= The total number of branch is %d\n", branch);
	printf("======= The total number of taint pair is %d\n", taintpair);
}

void analyze_corelist(void){
//fist round of analysis using taint
	
	taintpair = 0;
	branch = 0;
	inst_tainted = malloc(re_ds.instnum * sizeof(int));
	memset(inst_tainted, 0, re_ds.instnum*sizeof(int));
	taint_analysis();
	free(inst_tainted);
}








