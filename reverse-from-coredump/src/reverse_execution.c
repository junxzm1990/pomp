#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include "reverse_instructions.h"
#include "reverse_log.h"
#include "global.h"
#include "reverse_exe.h"
#include "inst_data.h"

re_t re_ds; 

int main(int argc, char *argv[]){
	
	size_t instnum;
	int result; 
	
	elf_core_info *core_info;
	elf_binary_info *binary_info;
	coredata_t * coredata; 
	x86_insn_t * rawinstlist; 

	if (argc != 4){
		LOG(stderr, "Help: %s coredump binary_path instruction_file\n", argv[0]);
		LOG(stderr, "      You must make sure that binary file,all the library files are in the directory defined by binary_path\n");
		exit(1);
	}

//pre-processing
//set path to global path variables
	set_core_path(argv[1]);
	set_bin_path(argv[2]);
	set_inst_path(argv[3]);


//parse core dump
	core_info = parse_core(get_core_path()); 
	if (!core_info) {
        	LOG(stderr,"ERROR: The core file is not parsed correctly");
        	exit(1);
	}
	
//parse binaries
	binary_info = parse_binary(core_info); 
	if (!binary_info) {
		LOG(stderr,"ERROR: The binary file is not parsed correctly");
		exit(1); 
   	} 

//load data from core dump, including registers and memory
	coredata = load_coredump(core_info, binary_info);
	if (!coredata) {
		LOG(stderr,"ERROR: Cannot load data from core dump");
		exit(1); 
   	}
	print_registers(coredata);

//load all the instructions in a reversed manner
	instnum = countvalidaddress(get_inst_path());
	if(instnum < 0){
		LOG(stderr, "ERROR: read file error when counting linenum\n");
		exit(1);
	}
	
	rawinstlist = (x86_insn_t *)malloc(instnum * sizeof(x86_insn_t));
	if (!rawinstlist){
		LOG(stderr, "ERROR: malloc error in main\n");
		exit(1);
	}

	memset(rawinstlist, 0, instnum * sizeof(x86_insn_t));
	result = load_trace(core_info, binary_info, get_inst_path(), rawinstlist);

	if (result < 0) {
		LOG(stderr, "ERROR: error in loading all the instructions\n");
		assert(0);
	}

#ifdef LOG_INSTRUCTIONS
	log_instructions(rawinstlist, instnum);
	return 0;
#endif

//main function of reverse exectuion
	INIT_RE(re_ds, instnum, rawinstlist, coredata);
	reverse_instructions();


//do some cleanup here
	destroy_instlist(rawinstlist);
	destroy_core_info(core_info);
	destroy_bin_info(binary_info);
}
