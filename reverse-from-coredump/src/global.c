#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "access_memory.h"
#include "elf_core.h"
#include "elf_binary.h"
#include "insthandler.h"
#include "disassemble.h"
#include "thread_selection.h"

char *core_path;
char *bin_path; 
char *inst_path; 


#ifdef DATA_LOGGED
char *log_path;
char *xmm_path; 
#endif

#ifdef BIN_ALIAS
char *sum_path; 
#endif


elf_core_info *core_info;
elf_binary_info *binary_info;

void set_core_path(char *path){
	core_path = path;
}

void set_bin_path(char *path){
    bin_path = path;
}

void set_inst_path(char *path){
    inst_path = path;
}

char *get_core_path(void){
    return core_path;
}

char *get_bin_path(void){
    return bin_path;
}

char *get_inst_path(void){
    return inst_path;
}

void set_core_info(elf_core_info *coreinfo){
    core_info = coreinfo;
}

void set_bin_info(elf_binary_info *binaryinfo){
    binary_info = binaryinfo;
}

elf_core_info *get_core_info(void){
    return core_info;
}

elf_binary_info *get_bin_info(void){
    return binary_info;
}

#ifdef DATA_LOGGED
void set_log_path(char* path){
	log_path = path; 
}

char* get_log_path(void){
	return log_path; 
}

void set_xmm_path(char* path){
	xmm_path = path; 
}

char* get_xmm_path(void){
	return xmm_path; 
}

#endif


#ifdef BIN_ALIAS
void set_sum_path(char * path){
	sum_path = path; 
}

#endif


