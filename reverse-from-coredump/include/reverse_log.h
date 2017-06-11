#ifndef __REVERSE_LOG__
#define __REVERSE_LOG__

#include <libdis.h>
#include "list.h"
#include "reverse_exe.h"

#ifdef DEBUG
#define LOG(...) do { fprintf(__VA_ARGS__); } while (0)
#else
#define LOG(...)
#endif

/*
void print_info_of_all_instructions(appinst_t *instlist, unsigned long totalnum);
void print_info_of_one_instruction(appinst_t *appinst);
void print_knownlist(appinst_t *appinst);
void print_stoplist(appinst_t *appinst);
void print_reverselist(appinst_t *appinst);
void print_memchangelist(appinst_t *appinst);
void print_constraintlist(appinst_t *appinst);
void print_assumptionlist(appinst_t *appinst);
void print_defheadlist(appdefheadlist_t *head);
void print_all_stops(appinst_t *instlist, unsigned long totalnum);
void print_unresolved_write(appdefheadlist_t *defhead);
*/

void log_instructions(x86_insn_t *instlist, unsigned instnum);

void print_reg(x86_reg_t reg);

void print_assembly(x86_insn_t *inst);

void print_operand(x86_op_t opd);

void print_registers(coredata_t *coredata);

void print_operand_info(int opd_count, ...);

void print_all_operands(x86_insn_t *inst);

void print_deflist(re_list_t *re_deflist); 

void print_uselist(re_list_t *re_uselist);

void print_instlist(re_list_t *re_instlist);

void print_umemlist(re_list_t *re_umemlist);

void print_corelist(re_list_t *re_list);

void print_info_of_current_inst(re_list_t *inst);

void alias_print_info_of_current_inst(re_list_t *inst);

void print_value_of_node(valset_u val, enum x86_op_datatype datatype);

void print_usenode(use_node_t *usenode);

void print_defnode(def_node_t *defnode);

void print_instnode(inst_node_t *instnode);

void print_node(re_list_t *node);
#endif
