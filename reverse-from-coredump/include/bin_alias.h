#ifdef BIN_ALIAS
#ifndef __BIN_ALIAS_H__
#define __BIN_ALIAS_H__



#define LARGE 1
#define EQUAL 0
#define LESS -1

enum sumtype{
	Skip = 0,
	Ro
};

void adjust_func_boundary(re_list_t* inst);
void init_reg_use(re_list_t* usenode, re_list_t* uselist);
void init_bin_alias(void);
void insert_pair(alias_pair_t** tree, unsigned id1, unsigned id2);
alias_pair_t* search_pair(alias_pair_t** tree, unsigned id1, unsigned id2);
#endif
#endif
