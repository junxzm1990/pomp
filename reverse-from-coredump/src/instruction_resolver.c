#include <stdio.h>
#include <libdis.h>
#include <malloc.h>
#include <assert.h>
#include <string.h>
#include "global.h"
#include "stopinst.h"
#include "disassemble.h"
#include "insthandler.h"
#include "access_memory.h"

void update_goodstatus(appdefheadlist_t *defhead){
    appdefheadlist_t *pos,*temp;
    list_for_each_entry_safe_reverse(pos, temp, &defhead->list, list) {
        if (pos->status == both_known) {
            pos->status = ok_now;
            if (!list_empty(&pos->uselist.list)) {
                appuselist_t *usepos, *usetemp;
                list_for_each_entry_safe_reverse(usepos, usetemp, &pos->uselist.list, list){
                    // if memory write, just continue; in resolve_deflist, only update memory address
                    if ((usepos->opd.access & op_write)&&(usepos->opd.type == op_expression)) continue;
                    LOG(stdout, "DEBUG: use update instruction 0x%lx ", usepos->index);
                    print_assembly(&instlist[usepos->index].inst);
                    LOG(stdout, "DEBUG: ");
                    print_operand(usepos->opd);
                    LOG(stdout, "\n");
                    if (usepos->opd.access & op_read) {
                        delete_unknown_by_use(pos, usepos);
                    }
                }
            }
            LOG(stdout, "DEBUG: define update instruction 0x%lx ", pos->index);
            print_assembly(&instlist[pos->index].inst);
            LOG(stdout, "DEBUG: ");
            print_operand(pos->opd);
            LOG(stdout, "\n");
            delete_unknown_by_defhead(pos);
        }
    }
}

void resolve_deflist(appdefheadlist_t *defhead){
    appdefheadlist_t *define;
    appuselist_t *use = NULL;
    appdefheadlist_t *next = NULL;
    int flag = 0;
    LOG(stdout, "\nDEBUG: ----start resolve Define-Use Chain in deflist----\n"); 
    list_for_each_entry(define, &defhead->list, list){
        // test
        appdefheadlist_t *simpletest = list_first_entry(&defhead->list, appdefheadlist_t, list);
        print_stoplist(instlist+simpletest->index);

        // test
        if (define->status == both_unknown) {
            LOG(stdout, "DEBUG: Skip index 0x%lx due to both unknown\n", define->index); 
            continue;
        }
        if (define->status == ok_now) {
            if (define->reason == rev_use) {
                // if this define is reversed by use, check whether the previous operand exists or not
                // if it does, and the its aftervalue is unknown, mark its aftervalue with beforevalue
                appdefheadlist_t *prev = define->prevdef;
                if ((prev != NULL) && (!(prev->status & after_known))) {
                    LOG(stdout, "DEBUG: previous index = 0x%lx\n", prev->index);
                    prev->aftervalue = define->beforevalue;
                    prev->status |= after_known;
                }
            } else {
                LOG(stdout, "DEBUG: Skip index 0x%lx due to ok now\n", define->index); 
            }
            if (define->reason == rev_assumption) {
                // it may be reversible by alias assumption
                appdefheadlist_t *prev = define->prevdef;
                if ((prev != NULL) && (prev->status & after_known)) {
                    if (prev->aftervalue != define->beforevalue) {
                        LOG(stdout, "ASSUMPTION: conflict here!\n");
                        // first entry in defheadlist must have assumptions that is added from before
                        appdefheadlist_t *defentry = list_first_entry(&defhead->list, appdefheadlist_t, list);
                        appassumption_t *first = list_first_entry(&instlist[defentry->index].assumptions.list, appassumption_t, list);
                        LOG(stdout, "ASSUMPTION: first->lindex = 0x%x\n", first->lindex);
                        instlist[first->lindex].conflict = 1;
                        instlist[first->lindex].cfttype = cft_dstmismatch;
                        LOG(stdout, "ASSUMPTION: Already find conflict in define-use chain\n");
                    }
                }
            }
            continue;
        }
        LOG(stdout, "DEBUG: current->index - 0x%lx\n", define->index); 
        LOG(stdout, "DEBUG: operand status - 0x%x\t", define->status); 
        print_assembly(&(instlist[define->index].inst));
        if (define->status & before_known) {
            list_for_each_entry(use, &define->uselist.list, list){
                // this define-use chain is inferred by use
                if (use->reason == rev_use) {
                    LOG(stdout, "DEBUG: Just continue, because this use-def is infered by use\n");
                    continue;
                }
                if (use->usage) {
                    LOG(stdout, "DEBUG: Just continue, because this use entry has been used\n");
                    continue;
                }
                LOG(stdout, "DEBUG: use    ->index - 0x%lx ", use->index); 
                print_assembly(&(instlist[use->index].inst));
                appinst_t *appinst = instlist+use->index;
                x86_insn_t *inst = &(appinst->inst);
                x86_op_t *opd1 = NULL;
                switch (inst->type){
                // x86_operand_1st may not return dest operand, like push pop
                default:
                    opd1 = x86_operand_1st(inst);
                    break;
                }
                unsigned int valuebefore = define->beforevalue;
                LOG(stdout, "DEBUG: valuebefore - 0x%x\n", valuebefore); 

                unsigned int value;
                // set use entry usage
                use->usage = 1;
                // define reg, use reg
                if (defreg_usereg(define, use)) {
                    LOG(stdout, "DEBUG: Define register, Use register\n");
                    set_value_to_reg(instlist+use->index, use->opd.data.reg, valuebefore);
                    value = get_result_from_inst(appinst);
                    LOG(stdout, "DEBUG: instruction result - 0x%x\n", value); 
                    appdefheadlist_t *find = find_opd_with_use(defhead,use);
                    if ((find->reason == rev_assumption) && (find->status & after_known) && (find->aftervalue != value)) {
                        LOG(stdout, "DEBUG: Destination is reversed by assumption, not update\n");
                    } else {
                        find->status |= after_known;
                        find->aftervalue = value;
                        find->reason = rev_define;
                        LOG(stdout, "DEBUG: (Register)set index - 0x%lx aftervalue from index - 0x%lx with value - 0x%x\n", use->index, define->index, value);
                    }
                // define reg, use expression 
                } else if (defreg_useexp(define, use)) {
                    LOG(stdout, "DEBUG: Define register, Use expression\n");
                    set_value_to_reg(instlist+use->index, define->opd.data.reg, valuebefore);
                    // Check whether umem is 1st operand
                    // if push command, the first operand is src operand, so it does not satisfy this condition
                    if ((opd1->type == op_expression)&&(opd1->access == op_write)&&((memcmp(&opd1->data.expression, &use->opd.data.expression, sizeof(x86_ea_t))==0))) {
                        appdefheadlist_t *find = find_opd_with_use(defhead, use);
                        // if this unknown memory write is inferred by assumption, just ignore it
                        if ((find->addr_status)&&(find->status&after_known)&&(find->reason==rev_assumption)){
                            LOG(stdout, "DEBUG: No need to update value of UMW\n");
                        } else {
                            find->addr_status = true;
                            find->address = get_address_from_expression(appinst, use->opd.data.expression);
                            find->reason = rev_define;
                            LOG(stdout, "DEBUG: (Memory)set index - 0x%lx address from index - 0x%lx with beforevalue - 0x%x\n", use->index, define->index, find->address);
                            update_pndef(find);
                            if ((find->nextdef != NULL) && (!(find->nextdef->status & before_known))){
                                LOG(stdout, "DEBUG: This memory value depends on other operand\n");
                            } else {
                                find->aftervalue = get_value_from_opd(instlist+find->index, &find->opd);
                                find->status |= after_known;

                                x86_op_t *srcopd = x86_get_src_operand(&instlist[find->index].inst);
                                add_reversible(instlist+find->index, srcopd, find->aftervalue, find->aftervalue, rev_use);
                            }
                        }
                    } else {
                        // check this memory read is in the assumption 
                        Elf32_Addr address = get_address_from_expression(appinst, use->opd.data.expression);
                        if (check_unknown_write(&urmdefhead)&&(check_read_assumption(appinst, use))) {
                            LOG(stdout, "DEBUG: This read is in the assumption\n"); 
                            // check read conflict assumption 
                            if (check_conflict_assumption(appinst, &use->opd)) {
                                LOG(stdout, "DEBUG: This read has conflict with the assumption\n"); 
                            }
                        }
                        value = get_result_from_inst(appinst);
                        LOG(stdout, "DEBUG: instruction result - 0x%x\n", value); 
                        // one instruction may have two or more defheads
                        appdefheadlist_t *find = find_opd_with_use(defhead, use);
                        find->status |= after_known;
                        find->aftervalue = value;
                        find->reason = rev_define;
                        LOG(stdout, "DEBUG: (Memory)set index - 0x%lx aftervalue from index - 0x%lx with beforevalue - 0x%x\n", use->index, define->index, value);
                    }
                // def expression, use expression
                } else if (defexp_useexp(define, use)) {
                    LOG(stdout, "DEBUG: Define expression, Use expresion\n");
                    set_value_to_opd(instlist+use->index, &use->opd, valuebefore);
                    value = get_result_from_inst(appinst);
                    LOG(stdout, "DEBUG: instruction result - 0x%x\n", value); 
                    appdefheadlist_t *find = find_opd_with_use(defhead,use);
                    find->status |= after_known;
                    find->aftervalue = value;
                    LOG(stdout, "DEBUG: (Memory)set index - 0x%lx aftervalue from index - 0x%lx with value - 0x%x\n", use->index, define->index, value);
                }
            }
        }
        if ((define->status&after_known) && (define->defstatus&next_known)) {
            if (define->nextdef->status & before_known) {
                LOG(stdout, "DEBUG: next   ->index - 0x%lx ", define->nextdef->index); 
                print_assembly(&(instlist[define->nextdef->index].inst));
                LOG(stdout, "DEBUG: The aftervalue of next definition is known\n"); 
            } else {
                LOG(stdout, "DEBUG: next   ->index - 0x%lx ", define->nextdef->index); 
                print_assembly(&(instlist[define->nextdef->index].inst));
                define->nextdef->status |= before_known;
                define->nextdef->beforevalue = define->aftervalue;
		
		//deal with 128 bit operand here
		//memcpy(define->nextdef->xmmbefore, define->xmmafter, XMMSIZE);
                define->nextdef->reason = rev_define;
                LOG(stdout, "DEBUG: set index - 0x%lx beforevalue from index - 0x%lx with aftervalue - 0x%x\n", define->nextdef->index, define->index, define->aftervalue);
            }
        }
        LOG(stdout, "\n");
    }
    update_goodstatus(defhead);
    LOG(stdout, "DEBUG: ----end   resolve Define-Use Chain in deflist----\n"); 
}

void resolve_uselist(appdefheadlist_t *defhead, appuselist_t *useentry){
    LOG(stdout, "\nDEBUG: ----start resolve Define-Use Chain in uselist----\n"); 
    appdefheadlist_t *next = useentry->defentry;
    useentry->usage = 1;

    // the use for bl is in the uselist of define entry for ebx
    if ((useentry->opd.type == op_register) && (useentry->opd.data.reg.alias == next->opd.data.reg.id)) {
        LOG(stdout, "DEBUG: Could not update the beforevalue because register alias\n");
    } else {
        next->reason = rev_use;
        next->status |= before_known;
        next->beforevalue = useentry->value;
        LOG(stdout, "DEBUG: set index - 0x%lx beforevalue from index - 0x%lx with aftervalue by use - 0x%x\n", next->index, useentry->index, useentry->value);
        // set opd value in [next->index, useentry->index]
        int i=0;
        for (i=next->index;i<=useentry->index;i++) {
            set_value_to_opd(instlist+i, &next->opd, useentry->value);
        }
    }
    LOG(stdout, "DEBUG: ----end   resolve Define-Use Chain in uselist----\n"); 
}

// check constraint with assumption
int resolve_assumption(appinst_t *appinst){
    // only try to resolve the first assumption one time
    appassumption_t *appasp = list_first_entry(&appinst->assumptions.list, appassumption_t, list);
    Elf32_Addr address = get_address_from_expression(instlist+appasp->rindex, appasp->right.data.expression);
    // src operand in the left of assumption
    x86_op_t *srcopd = x86_get_src_operand(&instlist[appasp->lindex].inst);
    // dest operand in the right of assumption
    x86_op_t *dstopd = x86_get_dest_operand(&instlist[appasp->rindex].inst);
    // get the value from assumed 
    unsigned int value = get_value_from_address(instlist+appasp->lindex, address, appasp->left.datatype);

    // set address and aftervalue for unknown memory write
    appdefheadlist_t *alias = check_may_alias_write(&urmdefhead, appinst);
    alias->reason = rev_assumption;
    alias->addr_status = true;
    alias->address = address;
    alias->aftervalue = value;
    alias->status |= after_known;
    add_opd_in_uselist(appinst-instlist, &urmdefhead, &appasp->right);
    // update previous and next definition when we assume memory alias at first
    update_pndef(alias);

    appuselist_t *useentry = NULL;
    appdefheadlist_t *next = NULL;
    switch (check_expression_registers(appasp->left.data.expression)) {
    case 1:
        resolve_base_index_reg(instlist+appasp->lindex, appasp->left.data.expression, address);
        if ((dstopd->type == op_register) && (compare_regs(dstopd->data.reg, appasp->left.data.expression.base))){
            appdefheadlist_t *basereg = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
            basereg->aftervalue = address;
            basereg->status |= after_known;
            // set beforevalue if the dest operand of memory read
            // is the same with the base register of memory write
            LOG(stdout, "DEBUG: BeforeValue is known\n");
            alias->beforevalue = address;
            alias->status |= before_known;
        }
        useentry = find_use_by_opd(&urmdefhead, &appasp->left, appasp->lindex);
        useentry->reason = rev_assumption;
        useentry->usage = 1;
        appdefheadlist_t *next = useentry->defentry;
        next->beforevalue = get_value_from_reg(instlist+appasp->lindex, appasp->left.data.expression.base);
        next->status |= before_known;
        next->reason = rev_assumption;
        break;
    case 2:
        resolve_base_index_reg(instlist+appasp->lindex, appasp->left.data.expression, address);
        if ((dstopd->type == op_register) && (compare_regs(dstopd->data.reg, appasp->left.data.expression.index))){
            appdefheadlist_t *indexreg = list_first_entry(&urmdefhead.list, appdefheadlist_t, list);
            indexreg->aftervalue = address;
            indexreg->status |= after_known;
            // set beforevalue if the dest operand of memory read
            // is the same with the base register of memory write
            LOG(stdout, "DEBUG: BeforeValue is known\n");
            alias->beforevalue = address;
            alias->status |= before_known;
        }
        useentry = find_use_by_opd(&urmdefhead, &appasp->left, appasp->lindex);
        useentry->reason = rev_assumption;
        useentry->usage = 1;
        next = useentry->defentry;
        next->beforevalue = get_value_from_reg(instlist+appasp->lindex, appasp->left.data.expression.index);
        next->status |= before_known;
        next->reason = rev_assumption;
        break;
    case 3:
        break;
    }

    // resolve define list through constraints obtained from assumption
    resolve_deflist(&urmdefhead);

    // if the src operand of unknown memory write is unknown, just add result inferred by assumption
    // else check whether the value inferred by assumption is right
    appuselist_t *srcuse = find_use_by_opd(&urmdefhead, srcopd, appasp->lindex);

    if ((srcuse != NULL) && (!(srcuse->defentry->status & before_known))) {
        // add reversible source operand
        add_reversible(instlist+appasp->lindex, srcopd, value, value, rev_assumption);
        srcuse->reason = rev_use;
        srcuse->usage = 1;
        srcuse->value = value;
        resolve_uselist(&urmdefhead, srcuse);
    } else {
        int srcvalue = get_value_from_opd(instlist+appasp->lindex, srcopd);
        if (value == srcvalue) {
            LOG(stdout, "CONFLICT: Assumption is OK\n");
            // set address and aftervalue for unknown memory write
        } else {
            LOG(stdout, "CONFLICT: Assumption is wrong\n");
            instlist[appasp->lindex].conflict = 1;
            instlist[appasp->lindex].cfttype = cft_srcmismatch;
        }
    }
    return 0;
}
// esp is unknown caused by the `index`th instruction
void resolve_esp_reg(appinst_t *instlist, unsigned long index, unsigned long totalnum) {
    int i = 0, flag = 0;;
    long disp = 0;
    x86_insn_t *inst; 
    // Maybe I need to check whether ebp is modified or not
    x86_reg_t esp, ebp;
    memset(&esp, 0, sizeof(x86_reg_t));
    memset(&ebp, 0, sizeof(x86_reg_t));
    x86_reg_from_id(x86_sp_reg(), &esp);
    x86_reg_from_id(get_ebp_id(), &ebp);
    appdefheadlist_t *ebpdefentry = find_reg_in_deflist(&urmdefhead, &ebp);
    if ((ebpdefentry != NULL) && (!(ebpdefentry->status & before_known))) {
        LOG(stderr, "ERROR: EBP is already unknown here. No clue to recover esp\n");
        assert(0);
    } else if ((ebpdefentry != NULL) && (ebpdefentry->status & before_known)) {
        LOG(stdout, "DEBUG: EBP value is already known due to known before value\n");
        set_value_to_reg(instlist+index, ebp, ebpdefentry->beforevalue);
    } else {
        LOG(stdout, "DEBUG: Current EBP value is able to use\n");
    }
    unsigned int value = get_value_from_reg(instlist+index, ebp);
    x86_op_t *dstopd, *srcopd, *immopd;
    LOG(stdout, "RESOLVE_ESP: instruction that makes esp unknown is %ld\n", index+1);
    for (i = index+1; i < totalnum; i++) {
        inst = &instlist[i].inst;
        //print_assembly(inst);
        switch (inst->type) {
        case insn_mov:
            dstopd = x86_get_dest_operand(inst);
            srcopd = x86_get_src_operand(inst);
            if (x86_opd_is_register(dstopd) && compare_regs(dstopd->data.reg, esp)) {
                LOG(stdout, "RESOLVE_ESP: destination operand is esp register\n");
                assert(0);
            }
            if (x86_opd_is_register(srcopd) && compare_regs(srcopd->data.reg, esp)) {
                LOG(stdout, "RESOLVE_ESP: ");
                print_assembly(inst);
                LOG(stdout, "RESOLVE_ESP: src operand is esp register\n");
                if (x86_opd_is_register(dstopd) && compare_regs(dstopd->data.reg, ebp)) {
                    flag = 1;
                    LOG(stdout, "RESOLVE_ESP: dest operand is ebp register\n");
                    value += disp;
                    set_value_to_reg(instlist+index, esp, value);
                    LOG(stdout, "RESOLVE_ESP: The value of resolved ESP is 0x%x\n", value);
                }
            }
            break;
        case insn_sub:
            dstopd = x86_get_dest_operand(inst);
            srcopd = x86_get_src_operand(inst);
            if (x86_opd_is_register(dstopd) && compare_regs(dstopd->data.reg, esp)) {
                LOG(stdout, "RESOLVE_ESP: ");
                print_assembly(inst);
                LOG(stdout, "RESOLVE_ESP: destination operand is esp register\n");
                disp -= get_value_from_opd(instlist+i, srcopd);
            }
            break;
        case insn_add:
            dstopd = x86_get_dest_operand(inst);
            srcopd = x86_get_src_operand(inst);
            if (x86_opd_is_register(dstopd) && compare_regs(dstopd->data.reg, esp)) {
                LOG(stdout, "RESOLVE_ESP: ");
                print_assembly(inst);
                LOG(stdout, "RESOLVE_ESP: destination operand is esp register\n");
                disp += get_value_from_opd(instlist+i, srcopd);
            }
            break;
        case insn_mul:
            break;
        case insn_return:
            LOG(stdout, "RESOLVE_ESP: ");
            print_assembly(inst);
            disp += 4;

            Elf32_Addr retaddr = instlist[i-1].inst.addr;
            LOG(stdout, "RESOLVE_ESP: Return address is 0x%x\n", retaddr);
            // search return address in the segment in which ebp is 
            Elf32_Addr espaddr = search_retaddr_in_segment(instlist+index, retaddr);
            // result of search_ret_addr_in_segment == ebp value, fail to find return address on stack
            if (espaddr == value) {
                LOG(stdout, "RESOLVE_ESP: No such return address on the stack\n");
            } else {
                flag = 1;
                LOG(stdout, "RESOLVE_ESP: ESP address is 0x%x\n", espaddr);
                espaddr += disp;
                set_value_to_reg(instlist+index, esp, espaddr);
                LOG(stdout, "RESOLVE_ESP: The value of resolved ESP is 0x%x\n", espaddr);
            }
            break;
        case insn_call:
            LOG(stdout, "RESOLVE_ESP: ");
            print_assembly(inst);
            disp -= 4;
            break;
        case insn_pop:
            LOG(stdout, "RESOLVE_ESP: ");
            print_assembly(inst);
            disp += 4;
            break;
        case insn_push:
            LOG(stdout, "RESOLVE_ESP: ");
            print_assembly(inst);
            disp -= 4;
            break;
        case insn_jcc:
        case insn_movcc:
        case insn_cmp:
        case insn_jmp:
        case insn_test:
        case insn_xor:
        case insn_or:
        case insn_ror:
        case insn_and:
        case insn_neg:
        case insn_nop: 
            break;
        default:
            LOG(stderr, "ERROR: unknown instruction with type 0x%x\n", inst->type);
            assert(0);
            break;
        }
        if (flag) break;
    }
    LOG(stdout, "RESOLVE_ESP: corresponding esp define/use instruction is %d\n", i+1);

    appdefheadlist_t *espentry = find_reg_in_deflist(&urmdefhead, &esp);
    if (espentry != NULL) {
        espentry->beforevalue = value;
        espentry->status |= before_known;
    } else {
        LOG(stdout, "ERROR: No esp register define entry\n");
    }
}

// resolve_base_index_reg when the address of expression is known
void resolve_base_index_reg(appinst_t *appinst, x86_ea_t exp, Elf32_Addr address){
    unsigned int value = 0;
    LOG(stdout, "DEBUG: ----start get base/index value from expression----\n");
    LOG(stdout, "DEBUG: disp: 0x%x, disp_sign: %d, disp_size: %d\n", exp.disp, exp.disp_sign, exp.disp_size);
    value = address - exp.disp;
    switch (check_expression_registers(exp)) {
    case 1:
        LOG(stdout, "DEBUG: base register value = 0x%x\n", value);
        set_value_to_reg(appinst, exp.base, value);
        break;
    case 2:
        LOG(stdout, "DEBUG: index register value = 0x%x\n", value);
        set_value_to_reg(appinst, exp.index, value);
        break;
    case 3:
        // Nothing to do
        // index + base = value
        break;
    }
    LOG(stdout, "DEBUG: ----end   get base/index value from expression----\n");
}
