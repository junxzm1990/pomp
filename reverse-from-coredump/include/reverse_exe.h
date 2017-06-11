#ifndef __REV_EXE__
#define __REV_EXE__

#include <stdbool.h>
#include "elf_core.h"
#include "list.h"
#include "inst_data.h"
#include <setjmp.h>

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

typedef union valset_struct{
	unsigned char byte; 	 /* 1-byte */
	unsigned short word; 	 /* 2-byte */
	unsigned long dword; 	 /* 4-byte */
	unsigned long qword[2];	 /* 8-byte */
	unsigned long dqword[4]; /* 16-byte*/
}valset_u; 


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

}use_node_t; 


typedef struct inst_node_struct{
	unsigned inst_index; 
	corereg_t corereg; 
	unsigned funcid;
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

	unsigned current_id;
	unsigned alias_id;
	size_t instnum;

	jmp_buf aliasret;

	x86_insn_t * instlist; 
	coredata_t * coredata; 
	re_list_t head; 
	re_list_t aliashead;

	int alias_offset; 	
	int rec_count;
	bool resolving;

	x86_op_t* root;

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

re_list_t *get_entry_by_id(unsigned id);

re_list_t *get_entry_by_inst_id(unsigned inst_index);

unsigned maxfuncid();
#endif
