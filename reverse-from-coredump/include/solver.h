#ifndef __SOLVER_H__
#define __SOLVER_H__

#ifdef WITH_SOLVER
#include<z3.h>
#include "reverse_exe.h"

#define SYMBUF 20
#define SYMSIZE 16
#define BITOFBYTE 8
#define VALUNITSIZE 4

Z3_ast mk_var(Z3_context ctx, const char * name, Z3_sort ty);
void id_to_symname(int id, char * name);
Z3_ast val_to_bv(valset_u val, size_t size);
Z3_lbool check_alias_by_constraint(re_list_t* node1, re_list_t*node2, bool alias, int offset);
Z3_lbool constraint_check(Z3_ast assert);

bool adjust_use_constraint(re_list_t *node);
bool adjust_def_constraint(re_list_t * node);


void add_constraint(Z3_ast constraint);

void add_address_constraint(re_list_t* node1, re_list_t* node2, bool alias, int offset);
void add_solver(re_list_t* inst, re_list_t **src, re_list_t **dst, int nuse, int ndef);
void sub_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
void inc_solver(re_list_t* inst, re_list_t **src, re_list_t **dst, int nuse, int ndef);
void dec_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
void shl_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
void shr_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
void rol_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
void ror_solver(re_list_t **src, re_list_t **dst, int nuse, int ndef);
#endif
#endif
