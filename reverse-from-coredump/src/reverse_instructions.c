#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "reverse_exe.h"
#include "analyze_result.h"

unsigned long reverse_instructions(void){

	unsigned index; 
	re_list_t *curinst, *previnst; 
	re_list_t *entry; 

	re_list_t re_deflist, re_uselist, re_instlist;  	

	//init the main linked list
	INIT_LIST_HEAD(&re_ds.head.list);
	INIT_LIST_HEAD(&re_ds.head.umemlist);

	re_ds.resolving = false; 	

	for(index = 0; index < re_ds.instnum; index++){

		if (verify_useless_inst(re_ds.instlist + index)) {
			continue;
		}

		//insert the instruction data into the current linked list
		curinst = add_new_inst(index);
		if( !curinst){
			assert(0);
		}

		
		print_instnode(curinst->node);

		LOG(stdout, "\n------------------Start of one instruction analysis-----------------\n");

		int handler_index = insttype_to_index(re_ds.instlist[index].type);
		if (handler_index >= 0) {
			inst_handler[handler_index](curinst);
		} else {
			LOG(stdout, "instruction type %x\n", re_ds.instlist[index].type);
			assert(0);
		}

		print_info_of_current_inst(curinst);
		LOG(stdout, "------------------ End of one instruction analysis------------------\n");
	}


#ifdef BIN_ALIAS
//make another assumption here
//We assume the registers are recorded at the begining of the trace
//this somehow makes sense

	list_for_each_entry(entry, &re_ds.head.list, list){

		INIT_LIST_HEAD(&re_deflist.deflist);
		INIT_LIST_HEAD(&re_uselist.uselist);
		INIT_LIST_HEAD(&re_instlist.instlist);	
		
		if(entry->node_type != UseNode)
			continue; 

		init_reg_use(entry, &re_uselist);	
		re_resolve(&re_deflist, &re_uselist, &re_instlist);
	}

#endif
	
	re_ds.resolving = true; 	
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {

		if (entry->node_type == InstNode) {

			re_ds.curinstid = entry->id; 

			INIT_LIST_HEAD(&re_deflist.deflist);
			INIT_LIST_HEAD(&re_uselist.uselist);
			INIT_LIST_HEAD(&re_instlist.instlist);	
		
			add_to_instlist(entry, &re_instlist);
			re_resolve(&re_deflist, &re_uselist, &re_instlist);

			//add something here?
			//will this lead to endless looping?
			//let's give a try
			/*Due to the optimization in the alias analysis, 
				we may not be able to resolve some values,
				here we rectify such problems */
#ifdef  FIX_OPTM
			fix_optimization(entry);
#endif			

			resolve_heuristics(entry, &re_deflist, &re_uselist, &re_instlist);
			re_resolve(&re_deflist, &re_uselist, &re_instlist);
			print_info_of_current_inst(entry);
		}	
	}

	list_for_each_entry(entry, &re_ds.head.list, list) {

		 if (entry->node_type == InstNode) {			
			re_ds.curinstid = entry->id;
#ifdef  FIX_OPTM
                        fix_optimization(entry);
#endif
			print_info_of_current_inst(entry);

		}
	}

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {

		 if (entry->node_type == InstNode) {			

			if(entry->id == 64648)
				printf("Target hit\n");

			re_ds.curinstid = entry->id;
#ifdef  FIX_OPTM
                        fix_optimization(entry);
#endif
			print_info_of_current_inst(entry);

		}
	}

	
	re_ds.resolving = false; 		
	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {

		 if (entry->node_type == InstNode) {			

			if(entry->id == 64648)
				printf("Target hit\n");

			re_ds.curinstid = entry->id;
#ifdef  FIX_OPTM
                        fix_optimization(entry);
#endif
			print_info_of_current_inst(entry);

		}
	}

	print_corelist(&re_ds.head);
	analyze_corelist();
	print_umemlist(&re_ds.head);

	LOG(stdout, "Max Function Id is %d\n", maxfuncid());
	destroy_corelist();

	return 0;    
}
