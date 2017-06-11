#ifndef __GLOBAL__
#define __GLOBAL__

#include <libdis.h>
#include "elf_core.h"
#include "elf_binary.h"

extern char *core_path;
extern char *bin_path;
extern char *inst_path;

void set_core_path(char *path);
char * get_core_path(void);

void set_bin_path(char *path);
char * get_bin_path(void);

void set_inst_path(char *path);
char * get_inst_path(void);

void set_core_info(elf_core_info *coreinfo);
elf_core_info *get_core_info(void);

void set_bin_info(elf_binary_info *binaryinfo);
elf_binary_info *get_bin_info(void);


unsigned long countvalidaddress(char *filename);
/*
int load_binlib(char *argv[]);
Elf32_Addr get_gs_base_address(elf_core_info *core_info);

//int malloc_new_memory(appphdr_data_t *mem);
int index_in_appdata(appinst_t *appinst, Elf32_Addr address);
void update_operands(appinst_t *appinst, inverse_function *inverse);
Elf32_Addr get_address_from_expression(appinst_t *appinst, x86_ea_t expression);
Elf32_Addr get_address_from_offset(x86_op_t *opd);
unsigned char *get_pointer_from_address(appinst_t *appinst, Elf32_Addr address);
unsigned int get_value_from_address(appinst_t *appinst, Elf32_Addr address, enum x86_op_datatype datatype);
unsigned int get_value_from_expression(appinst_t *appinst, x86_op_t *opd);
unsigned int get_value_from_immediate(appinst_t *appinst, x86_op_t *opd);
unsigned int get_value_from_offset(appinst_t *appinst, x86_op_t *opd);
unsigned int get_value_from_opd(appinst_t *appinst, x86_op_t *opd);

void set_value_to_expression(appinst_t *appinst, x86_op_t *opd, unsigned int value);
void set_value_to_opd(appinst_t *appinst, x86_op_t *opd, unsigned int value);

unsigned int get_result_from_inst(appinst_t *appinst);

unsigned int *check_exist_in_coredump(appdata_t *appdata, unsigned int value, unsigned char byte_num);
int check_esp_is_unknown(appinst_t *appinst);
Elf32_Addr search_retaddr_in_segment(appinst_t *appinst, Elf32_Addr retaddr);


*/
#endif
