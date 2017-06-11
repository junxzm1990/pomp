#include <assert.h>
#include <libdis.h>
#include <stdbool.h>
#include "reverse_exe.h"
#include "insthandler.h"
#include "reverse_log.h"
#include "re_stackpointer.h"
#include "inst_opd.h"

#define REPLACE_HEAD(oldhead, newhead) \
	(oldhead)->next->prev = newhead;\
	(oldhead)->prev->next = newhead; 

re_list_t *check_esp_known_of_inst(re_list_t *inst) {
	re_list_t *entry;

	list_for_each_entry_reverse(entry, &inst->list, list) {

		if ((entry == &re_ds.head) || (entry->node_type == InstNode)) 
			return NULL;

		if (entry->node_type == UseNode) continue;

		if (entry->node_type == DefNode){
			if (x86_opd_is_esp(CAST2_DEF(entry->node)->operand) && 
				!((CAST2_DEF(entry->node)->val_stat) & BeforeKnown)) {
				return entry;
			}
		}

	}
	return NULL;

}


static void continue_exe_to_resolve_esp() {
	re_list_t *recinst = find_current_inst(&re_ds.head);
	int index = CAST2_INST(recinst->node)->inst_index + 1;
	
	re_list_t *unknownesp = check_esp_known_of_inst(recinst);

	re_list_t *curinst;
	valset_u tempval;
	int disp = 0;
	for (; index < re_ds.instnum; index++) {
		curinst = add_new_inst(index);
		if (!curinst) assert(0);
		
		LOG(stdout, "\n------------Start to resolve esp------------\n");
		print_instnode(curinst->node);

		int handler_index = insttype_to_index(re_ds.instlist[index].type);

		if (handler_index >= 0) {
			int result = esp_resolver[handler_index](curinst, &disp);
			if (result == MOVEBPESP) {
				re_list_t *ebp = list_last_entry(&curinst->list, re_list_t, list);
				if (CAST2_DEF(ebp->node)->val_stat & AfterKnown) {
					LOG(stdout, "LOG: esp is resolved\n");
					print_defnode(ebp->node);
					tempval.dword = CAST2_DEF(ebp->node)->afterval.dword + disp;
					assign_def_before_value(unknownesp, tempval);
					print_defnode(unknownesp->node);
					break;
				}
			}
			if (result == RETADDR) {
				re_list_t *esp = list_last_entry(&curinst->list, re_list_t, list);
				if (CAST2_DEF(esp->node)->val_stat & AfterKnown) {
					LOG(stdout, "LOG: esp is resolved\n");
					print_defnode(esp->node);
					tempval.dword = CAST2_DEF(esp->node)->afterval.dword + disp;
					assign_def_before_value(unknownesp, tempval);
					print_defnode(unknownesp->node);
					break;
				}
			}
		} else {
			assert(0);
		}
		
		LOG(stdout, "LOG: disp = %x\n", disp);
		LOG(stdout, "-------------End to resolve esp-------------\n");

	}
	if (!(CAST2_DEF(unknownesp->node)->val_stat & BeforeKnown)) {

		return;
		//assert("continue to the end of trace" && 0);
	}
}


void resolve_esp() {
	re_t oldre;
	
	re_list_t *unknownesp = check_esp_known_of_inst(find_current_inst(&re_ds.head));

// save old list head
	memcpy(&oldre, &re_ds, sizeof(re_t));

	REPLACE_HEAD(&re_ds.head.list, &oldre.head.list);

	INIT_LIST_HEAD(&re_ds.head.list);
	fork_corelist(&re_ds.head, &oldre.head);	

	continue_exe_to_resolve_esp();

// save the beforevalue of esp
	re_list_t *newesp = get_new_exp_copy(unknownesp);
//	assert(CAST2_DEF(newesp->node)->val_stat & BeforeKnown);
	valset_u tempval = CAST2_DEF(newesp->node)->beforeval;

	delete_corelist(&re_ds.head);

// restore old list head
	memcpy(&re_ds, &oldre, sizeof(re_t));

	REPLACE_HEAD(&oldre.head.list, &re_ds.head.list);

	if(CAST2_DEF(newesp->node)->val_stat & BeforeKnown)
		assign_def_before_value(unknownesp, tempval);

	LOG(stdout, "\n$$$$$$$$$$$$$$$$$$$$$Resolved esp info: \n");
	print_defnode(unknownesp->node);
}


int esp_invalid_resolver(re_list_t *instnode, int *disp) {
	assert(0);
}


int esp_jcc_resolver(re_list_t *instnode, int *disp) {
	return 0;
}


int esp_jmp_resolver(re_list_t *instnode, int *disp) {
	return 0;
}


int esp_cmp_resolver(re_list_t *instnode, int *disp) {
	return 0;
}


int esp_test_resolver(re_list_t *instnode, int *disp) {
	return 0;
}


int esp_mov_resolver(re_list_t *instnode, int *disp) {
	x86_insn_t *inst = re_ds.instlist+CAST2_INST(instnode->node)->inst_index;	
	x86_op_t *dst = x86_get_dest_operand(inst);
	x86_op_t *src = x86_get_src_operand(inst);
	if (dst->type == op_register) {
		add_new_define(dst);
	}
	if (src->type == op_register) {
		add_new_use(src, Opd);
	}
	// mov ebp, esp
	if (x86_opd_is_ebp(dst) && x86_opd_is_esp(src)) {
		return MOVEBPESP;
	}
	return 0;
}


int esp_sub_resolver(re_list_t *instnode, int *disp) {
	x86_insn_t *inst = re_ds.instlist+CAST2_INST(instnode->node)->inst_index;	
	x86_op_t *dst = x86_get_dest_operand(inst);
	x86_op_t *src = x86_get_src_operand(inst);
	switch (get_operand_combine(inst)) {
	case dest_register_src_imm:
		if (x86_opd_is_esp(dst)) {
			if (src->datatype == op_byte) {
				*disp -= src->data.byte;
			} else if (src->datatype == op_word) {
				*disp -= src->data.word;
			} else if (src->datatype == op_dword) {
				*disp -= src->data.dword;
			}
		}
		break;
	}
	return 0;
}


int esp_add_resolver(re_list_t *instnode, int *disp) {
	x86_insn_t *inst = re_ds.instlist+CAST2_INST(instnode->node)->inst_index;	
	x86_op_t *dst = x86_get_dest_operand(inst);
	x86_op_t *src = x86_get_src_operand(inst);
	switch (get_operand_combine(inst)) {
	case dest_register_src_imm:
		if (x86_opd_is_esp(dst)) {
			if (src->datatype == op_byte) {
				*disp += src->data.byte;
			} else if (src->datatype == op_word) {
				*disp += src->data.word;
			} else if (src->datatype == op_dword) {
				*disp += src->data.dword;
			}
		}
		break;
	}
	return 0;
}


int esp_ret_resolver(re_list_t *instnode, int *disp) {
	unsigned index = CAST2_INST(instnode->node)->inst_index;
	unsigned retaddr = re_ds.instlist[index-1].addr;
	LOG(stdout, "LOG: retaddr is 0x%x\n", retaddr);
	x86_insn_t *inst = re_ds.instlist+index;	
	unsigned *dp;
	unsigned num;
	valset_u tempval;
	tempval.dword = retaddr;
	search_value_from_coredump(tempval, op_dword, &dp, &num);
	if (num == 1) {
		x86_op_t *esp = x86_implicit_operand_2nd(inst);
		re_list_t *defesp = add_new_define(esp);
		tempval.dword = dp[0];
		assign_def_after_value(defesp, tempval);
	} else {
		return 0;	//assert("More than one address candidate" && 0);
	}
	*disp += 4;
	free(dp);
	return RETADDR;
}
