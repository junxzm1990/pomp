#ifndef __ACCESS_MEMORY__
#define __ACCESS_MEMORY__

#include <libdis.h>
#include "elf_binary.h"
#include "ia32_reg.h"

int value_of_register(char *reg, Elf32_Addr *value, struct elf_prstatus thread);
int address_segment(elf_core_info *core_info, Elf32_Addr address);
off_t get_offset_from_address(elf_core_info *core_info, Elf32_Addr address);
int get_data_from_core(long int start, long int size, char *note_data);
int address_executable(elf_core_info *core_info, Elf32_Addr address);
int address_writable(elf_core_info *core_info, Elf32_Addr address);
int get_data_from_specified_file(elf_core_info *core_info, elf_binary_info *bin_info,  Elf32_Addr address, char *buf, size_t buf_size);
/*
int get_index_from_x86_reg_t(x86_reg_t reg);
unsigned int get_value_from_reg(appinst_t *inst, x86_reg_t reg);
void set_value_to_reg(appinst_t *appinst, x86_reg_t reg, unsigned int value);
*/
#endif
