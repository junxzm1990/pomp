#ifndef __BINARY__
#define __BINARY__

#include "elf_core.h"

typedef struct individual_binary_info_struct{
	char bin_name[FILE_NAME_SIZE];
	int parsed;
	size_t phdr_num;
	GElf_Phdr *phdr;
	Elf32_Addr base_address;
	Elf32_Addr end_address; 
}individual_binary_info; 

typedef struct elf_binary_info_struct{
	size_t bin_lib_num;
	individual_binary_info *binary_info_set;
}elf_binary_info;	

elf_binary_info *parse_binary(elf_core_info *core_info);

int destroy_bin_info(elf_binary_info *bin_info);

#endif
