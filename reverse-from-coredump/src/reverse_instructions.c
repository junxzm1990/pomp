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
#if 0
		if (check_esp_known_of_inst(curinst)) {
			LOG(stdout, "LOG: esp is unknown\n");
			resolve_esp();
			LOG(stdout, "LOG: esp is resolved\n");
			print_info_of_current_inst(curinst);
		}
#endif
		print_info_of_current_inst(curinst);

		LOG(stdout, "------------------ End of one instruction analysis------------------\n");
	}
/*
	re_ds.resolving = true; 	

	list_for_each_entry_reverse(entry, &re_ds.head.list, list) {

		if (entry->node_type == InstNode) {

			print_node(entry);

			INIT_LIST_HEAD(&re_deflist.deflist);
			INIT_LIST_HEAD(&re_uselist.uselist);
			INIT_LIST_HEAD(&re_instlist.instlist);	
		
			add_to_instlist(entry, &re_instlist);
			re_resolve(&re_deflist, &re_uselist, &re_instlist);

			resolve_heuristics(entry, &re_deflist, &re_uselist, &re_instlist);
				
			re_resolve(&re_deflist, &re_uselist, &re_instlist);
		}	
	}
*/
	LOG(stdout, "Max Function ID is %d\n", maxfuncid());

	//print_corelist(&re_ds.head);

	//analyze_corelist();

	//print_umemlist(&re_ds.head);

	destroy_corelist();
	return 0;    
}
