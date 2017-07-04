#ifndef __REV_EXE__
#define __REV_EXE__

#include <stdbool.h>
#include "elf_core.h"
#include "list.h"
#include "inst_data.h"
#include <setjmp.h>

#ifdef WITH_SOLVER
#include <z3.h>
#endif


#define INIT_RE(re_ds, a, b, c) \
	re_ds.instnum = a; \
	re_ds.instlist = b; \
	re_ds.coredata = c; \
	re_ds.current_id = 0;\
	re_ds.alias_id = 0; \
	re_ds.rec_count = 0;

#define INSERTED 0
#define EINSERT -1

#define SUB 1
#define SUPER 2
#define EXACT 3
#define OVERLAP 4

#define REC_LIMIT 2

#define RE_RES(red, reu, rei) \
	!list_empty(&red->deflist) || \
	!list_empty(&reu->uselist) || \
	!list_empty(&rei->instlist)

#define CAST2_DEF(def) ((def_node_t*)def)
#define CAST2_USE(use) ((use_node_t*)use)
#define CAST2_INST(inst) ((inst_node_t *) inst)

#define NOPD 16


#ifdef BIN_ALIAS
#define MAXFUNC 1000
#define MAXROM 1000
#endif


typedef union valset_struct{
	unsigned char byte; 	 /* 1-byte */
	unsigned short word; 	 /* 2-byte */
	unsigned long dword; 	 /* 4-byte */
	unsigned long qword[2];	 /* 8-byte */
	unsigned long dqword[4]; /* 16-byte*/
}valset_u; 


#ifdef DATA_LOGGED

#define MAX_REG_IN_INST 0x6

typedef struct opv{
	int reg_num; 
	valset_u val; 
}opv_t;

typedef struct operand_val{
	size_t regnum; 
	opv_t regs[MAX_REG_IN_INST];
}operand_val_t; 

typedef struct opval_list{
	int log_num; 
	operand_val_t *opval_list;
}opval_list_t; 

#endif 

enum nodetype{
	InstNode = 0x01,
	DefNode,
	UseNode
};


enum defstatus{
	Unknown = 0x00,
	BeforeKnown = 0x01,
	AfterKnown = 0x02
};

enum u_type{
	Opd = 0,
	Base,
	Index
};

#ifdef BIN_ALIAS

typedef struct func_info_struct{
	bool returned; 
	unsigned start;
	unsigned end; 

	unsigned stack_start;
	unsigned stack_end;
}func_info_t; 

//represents a function that does not touch memory outside
typedef struct mem_free_func{
	unsigned startaddr;
	unsigned endaddr; 
}mem_free_func_t;

typedef struct read_only_mem{
	unsigned startaddr; 
	unsigned endaddr; 
}read_only_mem_t;


typedef struct bin_alias_heu{
	unsigned mem_free_num;
	mem_free_func_t mff[MAXFUNC];

	unsigned read_only_num; 
	read_only_mem_t rom[MAXROM];

}bin_alias_heu_t; 

typedef struct alias_pair{
	unsigned id1; 
	unsigned id2; 	
	struct alias_pair *left; 
	struct alias_pair *right; 
}alias_pair_t;
#endif

//a key data struct for define node
//status: showing the value status
typedef struct def_node_struct{
	x86_op_t* operand; 			
	enum defstatus val_stat;

	valset_u beforeval; 
	valset_u afterval; 	

	//means unknown when 0
	unsigned address;
	//only for expression
	size_t addrnum;
	unsigned *addrset;

#ifdef WITH_SOLVER
	Z3_ast addresscst;
	Z3_ast beforecst;
	Z3_ast aftercst; 
	bool beforeconst;
	bool afterconst; 
#endif

}def_node_t;


typedef struct use_node_struct{
	enum u_type usetype;
	x86_op_t* operand; 

	bool val_known; 		
	valset_u val; 

	//means unknown when 0
	unsigned address;
	//only for expression
	size_t addrnum;
	unsigned *addrset;

#ifdef WITH_SOLVER
	Z3_ast constraint;
	Z3_ast addresscst; 
	bool constant;
#endif

}use_node_t; 


typedef struct inst_node_struct{
	unsigned inst_index; 
	corereg_t corereg; 
	unsigned funcid; 

#ifdef WITH_SOLVER
	Z3_ast constraint;
#endif 	

}inst_node_t;    

//data struct for node in re_list
//node_type: type of a node
//node: point to the contents of the node
//list: double linked list


typedef struct re_list_struct{

	unsigned id;

	enum nodetype node_type;
	void* node; 

//core linked list
	struct list_head list;

//for value resolving
	struct list_head deflist;
	struct list_head uselist;
	struct list_head instlist; 

//for alias
	struct list_head umemlist; 

}re_list_t;


//main data structure for reverse execution 
typedef struct re_struct{
	//which instruction id is being processed
	unsigned current_id;
	unsigned alias_id;

	//number of instruction in total
	size_t instnum;

	//trace location to return when conflict detected during alias verification
	jmp_buf aliasret;

	//the list of instructions
	x86_insn_t * instlist; 
	//the data loaded from core dump
	coredata_t * coredata; 

	//head of the core list
	re_list_t head; 

	//are these two really needed in this version?
	re_list_t aliashead;
	int alias_offset; 	

	//track the number of layer the alias verification is in
	int rec_count;
	//track if alias verification is enabled
	bool resolving;	

	//the operand that leads to the crash, as the starting point for taint analysis 
	x86_op_t* root;

#ifdef DATA_LOGGED
	//the list about log
	opval_list_t oplog_list; 
#endif

//set up the constraint context and solver using Z3
#ifdef WITH_SOLVER
	Z3_context zctx;
	Z3_solver solver;	
#endif

#ifdef BIN_ALIAS
	func_info_t flist[MAXFUNC];
	bin_alias_heu_t alias_heuristic; 
	alias_pair_t *atroot;
#endif
	unsigned curinstid; 

}re_t;


extern re_t re_ds;

unsigned long reverse_instructions();

re_list_t * add_new_inst(unsigned index);

re_list_t * add_new_define(x86_op_t * opd);

re_list_t * add_new_use(x86_op_t * opd, enum u_type type);

void assign_def_before_value(re_list_t * def, valset_u val);

void assign_def_after_value(re_list_t * def, valset_u val);

void re_resolve(re_list_t *re_uselist, re_list_t *re_deflist, re_list_t *re_instlist);

void resolve_use(re_list_t *re_uselist, re_list_t *re_deflist, re_list_t *re_instlist);

void resolve_define(re_list_t *re_uselist, re_list_t *re_deflist, re_list_t *re_instlist);

void resolve_inst(re_list_t *re_uselist, re_list_t *re_deflist, re_list_t *re_instlist);

int compare_two_targets(re_list_t* first, re_list_t * second);

bool ok_to_get_value(re_list_t *entry);

re_list_t * find_prev_use_of_use(re_list_t* use, int *type);

re_list_t * find_next_use_of_use(re_list_t* use, int *type);

re_list_t * find_prev_def_of_use(re_list_t* use, int *type);

re_list_t * find_next_def_of_use(re_list_t* use, int *type);

re_list_t * find_prev_def_of_def(re_list_t* def, int *type);

re_list_t * find_next_def_of_def(re_list_t* def, int *type);

re_list_t * find_inst_of_node(re_list_t *node);

size_t size_of_node(re_list_t* node);

// According to node_type, 
// check if this node in the corresponding list
bool check_node_in_list(re_list_t *node, re_list_t *list);

int insttype_to_index(enum x86_insn_type type);

int check_inst_resolution(re_list_t* inst);

bool node_is_exp(re_list_t* node, bool use);

bool address_is_known(re_list_t *node);

void res_expression(re_list_t * exp, re_list_t *uselist);

void assign_use_value(re_list_t *use, valset_u val);

void obtain_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef);

void obtain_inst_elements(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef);

void traverse_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, re_list_t* uselist, re_list_t* deflist, int *ndef, int *nuse);

void obtain_inst_operand(re_list_t* inst, re_list_t **use, re_list_t **def, int *nuse, int *ndef);

void split_expression_to_use(x86_op_t* opd);

bool check_next_unknown_write(re_list_t *listhead, re_list_t *def, re_list_t *target);

bool resolve_alias(re_list_t* exp, re_list_t* uselist);

void add_to_umemlist(re_list_t * exp);

void add_to_deflist(re_list_t *entry, re_list_t *listhead);

void add_to_uselist(re_list_t *entry, re_list_t *listhead);

void add_to_instlist(re_list_t *entry, re_list_t *listhead);

void add_to_instlist_tail(re_list_t *entry, re_list_t *listhead);

void remove_from_umemlist(re_list_t* exp);

void remove_from_deflist(re_list_t *entry, re_list_t *listhead);

void remove_from_uselist(re_list_t *entry, re_list_t *listhead);

void remove_from_instlist(re_list_t *entry, re_list_t *listhead);

void destroy_corelist();

void fork_corelist(re_list_t *newhead, re_list_t *oldhead);

void delete_corelist(re_list_t *head);

bool node1_add_before_node2(re_list_t *node1, re_list_t* node2);

re_list_t* get_new_exp_copy(re_list_t* exp);

void fork_umemlist();

void get_element_of_exp(re_list_t* exp, re_list_t ** index, re_list_t ** base);

bool unknown_expression(re_list_t * exp);

bool assign_mem_val(re_list_t* exp, valset_u * rv, re_list_t * use);

void zero_valset(valset_u *vt);

void one_valset(valset_u *vt);

void clean_valset(valset_u *vt, enum x86_op_datatype datatype, bool sign);

void sign_extend_valset(valset_u *vt, enum x86_op_datatype datatype);

bool sign_of_valset(valset_u *vt, enum x86_op_datatype datatype);

void get_src_of_def(re_list_t* def, re_list_t **use, int *nuse);

void resolve_heuristics(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist, re_list_t *re_instlist);

bool obstacle_between_two_targets(re_list_t *listhead, re_list_t* entry, re_list_t *target);

void correctness_check(re_list_t * instnode);

re_list_t *get_entry_by_id(unsigned id);

re_list_t *get_entry_by_inst_id(unsigned inst_index);


#ifdef FIX_OPTM
void fix_optimization(re_list_t* inst);
#endif


#endif
