#include <stdio.h>
#include <stdarg.h>
#include <libdis.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include "reverse_log.h"
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "access_memory.h"
#include "reverse_exe.h"

#if 0
// print all the elements attached with all the instructions
void print_info_of_all_instructions(appinst_t *instlist, unsigned long totalnum){
    int i;
    for (i = 0; i < totalnum; i++)
        print_info_of_one_instruction(instlist+i);
}

// print all the elements attached with one instruction
void print_info_of_one_instruction(appinst_t *appinst){
    //print_registers(appinst);
    print_constraintlist(appinst);
    print_knownlist(appinst);
    print_stoplist(appinst);
    print_reverselist(appinst);
    print_assumptionlist(appinst);
}
// print element in instruction known linked list
void print_knownlist(appinst_t *appinst){
    appknown_t *knowntemp = NULL;
    LOG(stdout, "DEBUG: Known Operand Set in 0x%x\n", appinst-instlist);
    list_for_each_entry(knowntemp, &(appinst->know.list),list){
        LOG(stdout, "DEBUG: ");
        print_operand(knowntemp->known);
        LOG(stdout, " with value 0x%x\n", knowntemp->value);
    }
    LOG(stdout, "\n");
}

// print element in instruction stop linked list
void print_stoplist(appinst_t *appinst){
    appstop_t *stoptemp = NULL;
    LOG(stdout, "DEBUG: Unknown Operand Set in 0x%x\n", appinst-instlist);
    list_for_each_entry(stoptemp, &(appinst->stop.list),list){
        LOG(stdout, "DEBUG: ");
        print_operand(stoptemp->unknown);
        LOG(stdout, "\n");
        switch (stoptemp->reason) {
        case dst_clear:
            LOG(stdout, "DEBUG: Destination is cleared\n");
            break;
        case src_destroy:
            LOG(stdout, "DEBUG: Source is destroyed\n");
            break;
        case bit_missing:
            LOG(stdout, "DEBUG: Some bits are missing\n");
            break;
        case unknown_before:
            LOG(stdout, "DEBUG: Already unknown in former instruction\n");
            break;
        }
    }
    LOG(stdout, "\n");
}

// print element in instruction reverse linked list
void print_reverselist(appinst_t *appinst){
    appreversible_t *reversetemp = NULL;
    LOG(stdout, "DEBUG: Reversible Operand Set in 0x%x\n", appinst-instlist);
    list_for_each_entry(reversetemp, &(appinst->reverse.list),list){
        LOG(stdout, "DEBUG: ");
        print_operand(reversetemp->reverse);
        LOG(stdout, "\n");
        LOG(stdout, "DEBUG: Beforevalue : 0x%x\n", reversetemp->beforevalue);
        LOG(stdout, "DEBUG: Aftervalue  : 0x%x\n", reversetemp->aftervalue);
        switch (reversetemp->reason) {
        case rev_define:
            LOG(stdout, "DEBUG: Reverse by last definition\n");
            break;
        case rev_use:
            LOG(stdout, "DEBUG: Reverse by use\n");
            break;
        case rev_condjmp:
            LOG(stdout, "DEBUG: Reverse by conditional jump\n");
            break;
        case rev_calljmp:
            LOG(stdout, "DEBUG: Reverse by uncondition jump, call, ret\n");
            break;
        case rev_inversefunc:
            LOG(stdout, "DEBUG: Reverse by inverse function\n");
            break;
        case rev_assumption:
            LOG(stdout, "DEBUG: Reverse by alias constraint\n");
            break;
        case rev_search_coredump:
            LOG(stdout, "DEBUG: Reverse by coredump search\n");
            break;
        default:
            LOG(stderr, "DEBUG: Unknown Reversible Reason\n");
            break;
        }
    }
    LOG(stdout, "\n");
}

// print element in constraint linked list
void print_constraintlist(appinst_t *appinst){
    appconstraint_t *temp = NULL;
    appconstraint_t *constraints = &appinst->constraints;
    LOG(stdout, "DEBUG: Constraint Set in 0x%x\n", appinst-instlist);

    list_for_each_entry(temp, &(constraints->list),list){
        //left operand
        if (temp->left.operation == 0) {
            if (temp->left.lstatus == before) {
                LOG(stdout, "DEBUG: Before_");
            } else {
                LOG(stdout, "DEBUG: After_");
            }
            print_operand(temp->left.a);
        } else {
            if (temp->right.lstatus == before) {
                LOG(stdout, "Before_");
            } else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.a);
            switch(temp->left.operation){
            case divs:
                LOG(stdout, " / ");
                break;
            case ands:
                LOG(stdout, " & ");
                break;
            default:
                LOG(stderr, "DEBUG: Unknown Operation %d\n", temp->right.operation);
                break;
            }
            if (temp->right.rstatus == before) {
                LOG(stdout, "Before_");
            }else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.b);
        }
        switch (temp->relation) {
        case equ:
            LOG(stdout, " = ");
            break;
        case ne:
            LOG(stdout, " != ");
            break;
        default:
            LOG(stderr, "DEBUG: Unknown Relation\n");
            break;
        }
        if (temp->right.operation == 0) {
            if (temp->right.lstatus == before) {
                LOG(stdout, "Before_");
            } else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.a);
            LOG(stdout,"\n");
        } else if((temp->right.operation == addr)||(temp->right.operation == negs)||(temp->right.operation == nots)) {
            if (temp->right.operation == addr)
                LOG(stdout, " & ");
            else if (temp->right.operation == negs)
                LOG(stdout, " - ");
            else if (temp->right.operation == nots)
                LOG(stdout, " ~ ");

            if (temp->right.lstatus == before) {
                LOG(stdout, "Before_");
            } else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.b);
            LOG(stdout,"\n");
        } else {
            if (temp->right.lstatus == before) {
                LOG(stdout, "Before_");
            } else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.a);
            switch (temp->right.operation) {
            case add:
                LOG(stdout, " + ");
                break;
            case sub:
                LOG(stdout, " - ");
                break;
            case mul:
                LOG(stdout, " x ");
                break;
            case divs:
                LOG(stdout, " / ");
                break;
            case quotient:
                LOG(stdout, " ... ");
                break;
            case leftrot:
                LOG(stdout, " <<< ");
                break;
            case rightrot:
                LOG(stdout, " >>> ");
                break;
            case leftshift:
                LOG(stdout, " << ");
                break;
            case rightshift:
                LOG(stdout, " >> ");
                break;
            case ands:
                LOG(stdout, " & ");
                break;
            case xors:
                LOG(stdout, " ^ ");
                break;
            case ors:
                LOG(stdout, " | ");
                break;
            default:
                LOG(stderr, "DEBUG: Unknown Operation2 %d\n", temp->right.operation);
                break;
            }
            if (temp->right.rstatus == before) {
                LOG(stdout, "Before_");
            } else {
                LOG(stdout, "After_");
            }
            print_operand(temp->right.b);
            LOG(stdout,"\n");
        }
    }
    LOG(stdout, "\n");
}

// print element in assumption linked list
void print_assumptionlist(appinst_t *appinst){
    appassumption_t *temp = NULL;
    appassumption_t *assumptions = &appinst->assumptions;
    LOG(stdout, "DEBUG: Assumption Set in 0x%x\n", appinst-instlist);

    list_for_each_entry(temp, &(assumptions->list),list){
        if (temp->holds == 1) {
            LOG(stdout, "DEBUG: holds ");
        } else {
            LOG(stdout, "DEBUG: unholds ");
        }
        print_operand(temp->left);
        LOG(stdout, " in 0x%x", temp->lindex);
        switch (temp->relation) {
        case equ:
            LOG(stdout, " = ");
            break;
        case ne:
            LOG(stdout, " != ");
            break;
        default:
            LOG(stderr, "DEBUG: Unknown Relation\n");
            break;
        }
        print_operand(temp->right);
        LOG(stdout, " in 0x%x", temp->rindex);
        LOG(stdout,"\n");
    }
    LOG(stdout, "\n");
}

// print element in defhead linked list
void print_defheadlist(appdefheadlist_t *defhead){
    appdefheadlist_t *temp = NULL;
    LOG(stdout, "\nDEBUG: -------------Define-Use Chain--------------\n");
    LOG(stdout, "DEBUG: Question Set \n");
    list_for_each_entry(temp, &defhead->list, list) {
        if (temp->opd.type == op_register) {
            LOG(stdout, "DEBUG: index = 0x%lx\n", temp->index);
            LOG(stdout, "DEBUG: operand = ");
            print_operand(temp->opd);
            LOG(stdout, "\n");
        } else if (temp->opd.type == op_expression) {
            LOG(stdout, "DEBUG: index = 0x%lx\n", temp->index);
            LOG(stdout, "DEBUG: operand = ");
            print_operand(temp->opd);
            LOG(stdout, "\n");
            switch (temp->base_status) {
            case 0:
                LOG(stdout, "DEBUG: No base register\n");
                break;
            case 1:
                LOG(stdout, "DEBUG: Base register is unknown\n");
                break;
            case 2:
                LOG(stdout, "DEBUG: Base register is known\n");
                break;
            }
            switch (temp->index_status) {
            case 0:
                LOG(stdout, "DEBUG: No index register\n");
                break;
            case 1:
                LOG(stdout, "DEBUG: Index register is unknown\n");
                break;
            case 2:
                LOG(stdout, "DEBUG: Index register is known\n");
                break;
            }
            if (temp->addr_status) {
                LOG(stdout, "DEBUG: address known - 0x%x\n", temp->address);
            } else {
                LOG(stdout, "DEBUG: address unknown\n");
                if (temp->addrset != NULL){
                    LOG(stdout, "DEBUG: but with super set: \n");
                    int i;
                    for (i=0;i<temp->addrnum;i++)LOG(stdout, "0x%.8x\t", temp->addrset[i]);
                    LOG(stdout, "\n");
                }
            }
        } else if (temp->opd.type == op_offset) {
            LOG(stdout, "DEBUG: index = 0x%lx\n", temp->index);
            LOG(stdout, "DEBUG: operand = ");
            print_operand(temp->opd);
            LOG(stdout, "\n");
            LOG(stdout, "DEBUG: address known - 0x%x\n", temp->address);
        }
        LOG(stdout, "DEBUG: Operand Status = 0x%x\n", temp->status);
        if (temp->status == both_unknown) {
            LOG(stdout, "DEBUG: Beforevalue and Aftervalue both are unknown\n");
        } else if (temp->status == before_known) {
            LOG(stdout, "DEBUG: Beforevalue is 0x%x\n", temp->beforevalue);
        } else if (temp->status == after_known) {
            LOG(stdout, "DEBUG: Aftervalue  is 0x%x\n", temp->aftervalue);
        } else if (temp->status == ok_now) {
            LOG(stdout, "DEBUG: Beforevalue is 0x%x\n", temp->beforevalue);
            LOG(stdout, "DEBUG: Aftervalue  is 0x%x\n", temp->aftervalue);
        }
        switch (temp->reason) {
        case rev_define:
            LOG(stdout, "DEBUG: Reverse Reason is Define\n");
            break;
        case rev_use:
            LOG(stdout, "DEBUG: Reverse Reason is Use\n");
            break;
        case rev_condjmp:
            LOG(stdout, "DEBUG: Reverse Reason is Conditional Jump\n");
            break;
        case rev_calljmp:
            LOG(stdout, "DEBUG: Reverse Reason is UnCondition Jump/Call\n");
            break;
        case rev_inversefunc:
            LOG(stdout, "DEBUG: Reverse Reason is inverse function\n");
            break;
        case rev_assumption:
            LOG(stdout, "DEBUG: Reverse Reason is Assumption\n");
            break;
        case rev_search_coredump:
            LOG(stdout, "DEBUG: Reverse Reason is Coredump Search\n");
            break;
        }
        LOG(stdout, "DEBUG: Defintion Status = 0x%x\n", temp->defstatus);
        if (temp->defstatus == pn_unknown) {
            LOG(stdout, "DEBUG: Previous and Next Definition both are unknown\n");
        } else if (temp->defstatus == next_known) {
            LOG(stdout, "DEBUG: Next Definition     is 0x%lx\n", temp->nextdef->index);
        } else if (temp->defstatus == prev_known) {
            LOG(stdout, "DEBUG: Previous Definition is 0x%lx\n", temp->prevdef->index);
        } else if (temp->defstatus == pn_known) {
            LOG(stdout, "DEBUG: Previous Definition is 0x%lx\n", temp->prevdef->index);
            LOG(stdout, "DEBUG: Next Definition     is 0x%lx\n", temp->nextdef->index);
        }
        LOG(stdout, "DEBUG: ----start in uselist---- \n");
        appuselist_t *use;
        list_for_each_entry(use, &temp->uselist.list, list){
            if (use->opd.type == op_register) {
                LOG(stdout, "DEBUG: index = 0x%lx\n", use->index);
                LOG(stdout, "DEBUG: name = %s\n", use->opd.data.reg.name);
            } else if (use->opd.type == op_expression) {
                LOG(stdout, "DEBUG: index = 0x%lx\n", use->index);
                LOG(stdout, "DEBUG: expression = ");
                print_operand(use->opd);
                LOG(stdout, "\n");
            } else if (use->opd.type == op_offset) {
                LOG(stdout, "DEBUG: index = 0x%lx\n", use->index);
                LOG(stdout, "DEBUG: expression = ");
                print_operand(use->opd);
                LOG(stdout, "\n");
            }
            switch (use->reason) {
            case rev_define:
                LOG(stdout, "DEBUG: Reverse Reason is Define\n");
                break;
            case rev_use:
                LOG(stdout, "DEBUG: Reverse Reason is Use\n");
                break;
            case rev_condjmp:
                LOG(stdout, "DEBUG: Reverse Reason is Conditional Jump\n");
                break;
            case rev_calljmp:
                LOG(stdout, "DEBUG: Reverse Reason is UnCondition Jump/Call\n");
                break;
            case rev_inversefunc:
                LOG(stdout, "DEBUG: Reverse Reason is inverse function\n");
                break;
            case rev_assumption:
                LOG(stdout, "DEBUG: Reverse Reason is Assumption\n");
                break;
            case rev_search_coredump:
                LOG(stdout, "DEBUG: Reverse Reason is Coredump Search\n");
                break;
            }
            if (use->usage) {
                LOG(stdout, "DEBUG: The operand has already been used\n");
            } else {
                LOG(stdout, "DEBUG: This operand is never used\n");
            }
            if (temp->status & before_known) {
                LOG(stdout, "DEBUG: The value of use entry is %x\n", use->value);
            }
        }
        LOG(stdout, "DEBUG: ----end   in uselist----\n");
        LOG(stdout, "\n");
    }
}

void print_all_stops(appinst_t *instlist, unsigned long totalnum){
    LOG(stdout, "DEBUG: Summary about all unsolved stop operands\n");
    int i = 0;
    appinst_t *appinst = NULL;
    for (i=0;i<totalnum;i++) {
        appinst = instlist + i;
        if (list_empty(&appinst->stop.list)) continue;
        LOG(stdout, "DEBUG: The 0x%x instruction has the following unsolved operand:\n", i);
        appstop_t *temp;
        list_for_each_entry(temp, &appinst->stop.list, list){
            LOG(stdout, "DEBUG: ");
            print_operand(temp->unknown);
            LOG(stdout, "\n");
            switch (temp->reason) {
            case dst_clear:
                LOG(stdout, "DEBUG: Destination is cleared\n");
                break;
            case src_destroy:
                LOG(stdout, "DEBUG: Source is destroyed\n");
                break;
            case bit_missing:
                LOG(stdout, "DEBUG: Some bits are missing\n");
                break;
            case unknown_before:
                LOG(stdout, "DEBUG: Already unknown in former instruction\n");
                break;
            }
        }
        LOG(stdout, "\n");
    }
}

void print_unresolved_write(appdefheadlist_t *defhead){
    appdefheadlist_t *temp;
    list_for_each_entry_reverse(temp, &defhead->list, list){
        if (temp->opd.type == op_expression) {
            if ((temp->addr_status) && (!(temp->status & before_known))) {
                LOG(stdout, "unresolved memory write - 0x%x\n", temp->address);
            }
        }
    }
}
#endif


void print_reg(x86_reg_t reg) {
	LOG(stdout, "%s", reg.name);
}


void print_assembly(x86_insn_t *inst){
	char debugline[MAX_INSN_STRING];
	x86_format_insn(inst, debugline, MAX_INSN_STRING, intel_syntax);
	LOG(stdout, "Current Instruction is %s.\n", debugline);
}


void print_operand(x86_op_t opd){
	char debugopd[MAX_OP_STRING];
	x86_format_operand(&opd, debugopd, MAX_OP_STRING, intel_syntax);
	LOG(stdout, "%s", debugopd);
}


// print all the registers for one instruction
void print_registers(coredata_t *coredata){
    LOG(stdout, "DEBUG: EBX - 0x%lx\n", coredata->corereg.regs[EBX]);
    LOG(stdout, "DEBUG: ECX - 0x%lx\n", coredata->corereg.regs[ECX]);
    LOG(stdout, "DEBUG: EDX - 0x%lx\n", coredata->corereg.regs[EDX]);
    LOG(stdout, "DEBUG: ESI - 0x%lx\n", coredata->corereg.regs[ESI]);
    LOG(stdout, "DEBUG: EDI - 0x%lx\n", coredata->corereg.regs[EDI]);
    LOG(stdout, "DEBUG: EBP - 0x%lx\n", coredata->corereg.regs[EBP]);
    LOG(stdout, "DEBUG: EAX - 0x%lx\n", coredata->corereg.regs[EAX]);
    LOG(stdout, "DEBUG: ESP - 0x%lx\n", coredata->corereg.regs[UESP]);
    LOG(stdout, "\n");
}


void print_operand_info(int opd_count, ...){
    va_list arg_ptr;
    x86_op_t *opd;
    va_start(arg_ptr, opd_count);
    int i = 0;
    LOG(stdout, "DEBUG: Operand num is %d\n", opd_count);
    for (i=0; i<opd_count; i++) {
        LOG(stdout, "DEBUG: %dth operand - ", i+1);
        opd=va_arg(arg_ptr, x86_op_t *);
        if (opd != NULL) {
            print_operand(*opd);
        } else {
            LOG(stdout, "NULL");
        }
        LOG(stdout, "\n");
    }
    va_end(arg_ptr);
}


void print_all_operands(x86_insn_t *inst) {

	LOG(stdout, "LOG: All operands num: %d\n", inst->operand_count);
	LOG(stdout, "LOG: Explicit operands num: %d\n", inst->explicit_count);
	
	x86_oplist_t *temp;
	for (temp=inst->operands;temp != NULL; temp=temp->next) {
		LOG(stdout, "LOG: operand type is %d\n", temp->op.type);
		print_operand(temp->op);
		LOG(stdout, "\n");
	}
}


void print_value_of_node(valset_u val, enum x86_op_datatype datatype) {
	switch (datatype) {
		case op_byte:
			LOG(stdout, "0x%x (byte)", val.byte);
			break;
		case op_word:
			LOG(stdout, "0x%x (word)", val.word);
			break;
		case op_dword:
			LOG(stdout, "0x%lx (dword)", val.dword);
			break;
		case op_qword:
			LOG(stdout, "0x%lx 0x%lx (qword)",
				val.qword[0], val.qword[1]);
			break;
		case op_dqword:
			LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
				val.dqword[0], val.dqword[1],
				val.dqword[2], val.dqword[3]);
			break;
		
		case op_ssimd:
			LOG(stdout, "0x%lx 0x%lx 0x%lx 0x%lx (dqword)",
                                val.dqword[0], val.dqword[1],
                                val.dqword[2], val.dqword[3]);
                        break;

		default:
			assert("No such datatype" && 0);
	}
}


void print_defnode(def_node_t *defnode){
	LOG(stdout, "LOG: Def Node with opd ");
	print_operand(*(defnode->operand));
	LOG(stdout, "\n");
	switch (defnode->val_stat) {
	case Unknown:
		LOG(stdout, "LOG: Both value are unknown\n");
		break;
	case BeforeKnown:
		LOG(stdout, "LOG: Before value are known\n");
		LOG(stdout, "LOG: Before Value ");
		print_value_of_node(defnode->beforeval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	case AfterKnown:
		LOG(stdout, "LOG: After value are known\n");
		LOG(stdout, "LOG: After  Value ");
		print_value_of_node(defnode->afterval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	case 0x3:
		LOG(stdout, "LOG: Both value are known\n");
		LOG(stdout, "LOG: Before Value ");
		print_value_of_node(defnode->beforeval, defnode->operand->datatype);
		LOG(stdout, "\n");
		LOG(stdout, "LOG: After  Value ");
		print_value_of_node(defnode->afterval, defnode->operand->datatype);
		LOG(stdout, "\n");
		break;
	}
	if (defnode->operand->type == op_expression){
		if (defnode->address != 0) {
			LOG(stdout, "LOG: address = 0x%x\n", defnode->address);
		} else {
			LOG(stdout, "LOG: address is unknown\n");
		}
	}
}


void print_usenode(use_node_t *usenode){
	LOG(stdout, "LOG: Use Node with ");
	switch (usenode->usetype) {
		case Opd:
			LOG(stdout, "Opd itself ");
			print_operand(*(usenode->operand));
			break;
		case Base:
			LOG(stdout, "Base Register ");
			print_reg(usenode->operand->data.expression.base);
			break;
		case Index:
			LOG(stdout, "Index Register ");
			print_reg(usenode->operand->data.expression.index);
			break;
	}
	LOG(stdout, "\n");
	if (usenode->val_known) {
		LOG(stdout, "LOG: Value is known\n");
		LOG(stdout, "LOG: Value ");
		switch (usenode->usetype) {
		case Opd:
			print_value_of_node(usenode->val, usenode->operand->datatype);
			break;
		case Base:
			print_value_of_node(usenode->val, op_dword);
			break;
		case Index:
			print_value_of_node(usenode->val, op_dword);
			break;
		}
		LOG(stdout, "\n");
	} else {
		LOG(stdout, "LOG: Value is unknown\n");
	}
	if ((usenode->usetype == Opd)&&(usenode->operand->type == op_expression)){
		if (usenode->address != 0) {
			LOG(stdout, "LOG: Address = 0x%x\n", usenode->address);
		} else {
			LOG(stdout, "LOG: Address is unknown\n");
		}
	}
}


void print_instnode(inst_node_t *instnode) {
	LOG(stdout, "LOG: Inst Node with index %d and function ID %x\n", instnode->inst_index, instnode->funcid);
	print_assembly(re_ds.instlist + instnode->inst_index);
}


void print_node(re_list_t *node){
	LOG(stdout, "LOG: Node ID is %d\n", node->id);
	switch (node->node_type) {
		case InstNode:
			print_instnode(CAST2_INST(node->node));
			break;
		case UseNode:
			print_usenode(CAST2_USE(node->node));
			break;
		case DefNode:
			print_defnode(CAST2_DEF(node->node));
			break;
		default:
			assert(0);
			break;
	}
}


// only print def list
void print_deflist(re_list_t *re_deflist) {
	re_list_t *entry;
	def_node_t *defnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of deflist:\n");
	list_for_each_entry_reverse(entry, &re_deflist->deflist, deflist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		defnode = CAST2_DEF(entry->node);
		print_defnode(defnode);
	}
	LOG(stdout, "=================================================\n");
}


// only print use list
void print_uselist(re_list_t *re_uselist) {
	re_list_t *entry;
	use_node_t *usenode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of uselist:\n");
	list_for_each_entry_reverse(entry, &re_uselist->uselist, uselist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		usenode = CAST2_USE(entry->node);
		print_usenode(usenode);
	}
	LOG(stdout, "=================================================\n");
}


// only print inst list
void print_instlist(re_list_t *re_instlist) {
	re_list_t *entry;
	inst_node_t *instnode;
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of instlist:\n");
	list_for_each_entry_reverse(entry, &re_instlist->instlist, instlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		instnode = CAST2_INST(entry->node);
		print_instnode(instnode);
	}
	LOG(stdout, "=================================================\n");
}


// In general, re_umemlist should be &re_ds.head
// This linked list is a global list
void print_umemlist(re_list_t *re_umemlist) {
	re_list_t *entry, *inst;
	
	unsigned umemnum = 0;

	LOG(stdout, "=================================================\n");
	LOG(stdout, "Item of umemlist:\n");
	list_for_each_entry_reverse(entry, &re_umemlist->umemlist, umemlist){
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
		inst = find_inst_of_node(entry);
		if (inst) {
			print_instnode(CAST2_INST(inst->node));
		} else {
			assert(0);
		}
		umemnum++;

	}
	LOG(stdout, "%d unknown memory write=================================================\n", umemnum);
}


// heavy print function 
// print all the elements in the core list
void print_corelist(re_list_t *re_list) {
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~Start of Core List~~~~~~~~~~~~~~~~~~~~~~\n");
	list_for_each_entry_reverse(entry, &re_list->list, list) {
		if (entry->node_type == InstNode) LOG(stdout, "\n");
		
		LOG(stdout, "=================================================\n");
		LOG(stdout, "LOG: Node ID is %d\n", entry->id);
		if (entry->node_type == InstNode) {
			print_instnode(CAST2_INST(entry->node));
		}
		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~~~~End of Core List~~~~~~~~~~~~~~~~~~~~~~~\n");

}


// only print all the operands of the current instruction 
void print_info_of_current_inst(re_list_t *inst){
	re_list_t *entry;
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~Start of Current Inst Info~~~~~~~~~~~~~~~~~~~\n");
	LOG(stdout, "LOG: Node ID is %d\n", inst->id);
	print_instnode(inst->node);
	list_for_each_entry_reverse(entry, &inst->list, list) {
		LOG(stdout, "=================================================\n");
		if (entry == &re_ds.head) break;
		if (entry->node_type == InstNode) break;

		LOG(stdout, "LOG: Node ID is %d\n", entry->id);

		if (entry->node_type == DefNode) {
			print_defnode(CAST2_DEF(entry->node));
		}
		if (entry->node_type == UseNode) {
			print_usenode(CAST2_USE(entry->node));
		}
	}
	LOG(stdout, "~~~~~~~~~~~~~~~~~~~~End of Current Inst info~~~~~~~~~~~~~~~~~~~~\n");
}


// log all the instructions to one file called "instructions"
void log_instructions(x86_insn_t *instlist, unsigned instnum){
	FILE *file;
	if ((file=fopen("instructions", "w")) == NULL) {
		LOG(stderr, "ERROR: instructions file open error\n");
		assert(0);
	}
	char inst_buf[MAX_INSN_STRING+15];
	int i;
	for (i=0;i<instnum;i++) {
		x86_format_insn(&instlist[i], inst_buf, MAX_INSN_STRING, intel_syntax);
		fprintf(file, "0x%08x:\t%s\n", instlist[i].addr, inst_buf);
	}
}

void print_maxfuncid() {
	LOG(stdout, "=================================================\n");
	LOG(stdout, "Max Function ID is %d\n", maxfuncid());
	LOG(stdout, "=================================================\n");
}
