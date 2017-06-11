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
#include "inst_data.h"

// Collect data, like register, memory, base address for gs selector
coredata_t * load_coredump(elf_core_info *core_info, elf_binary_info *binary_info){

	int index, segindex, threadnum;
	int offset = 0;
	coredata_t * coredata;	


//initialize coredata
	coredata = (coredata_t * )malloc(sizeof(coredata_t));
	if(!coredata)
		return NULL;

	coredata->coremem = (memseg_t*) malloc(core_info->phdr_num * sizeof(memseg_t));

	if(!coredata->coremem){
		free(coredata);
		return NULL;
	}	

	memset(coredata->coremem, 0, core_info->phdr_num * sizeof(memseg_t));

	segindex = 0;	
//copy memory from core dump or mapped file into coredata
	for(index = 0; index < core_info->phdr_num; index++){

		if (!(core_info->phdr[index].p_type & PT_LOAD))
			continue;

		coredata->coremem[segindex].data = 
			malloc(core_info->phdr[index].p_memsz);

		if(!coredata->coremem[segindex].data){
			//fix me later, as all data are not freed
			free(coredata->coremem);
			free(coredata);
			return NULL;
		}

		offset = get_offset_from_address(
			core_info, core_info->phdr[index].p_vaddr);

		if (offset == ME_NDUMP) {
			get_data_from_specified_file(
				core_info, binary_info, 
				core_info->phdr[index].p_vaddr, 
				coredata->coremem[segindex].data, 
				core_info->phdr[index].p_memsz);
		} else if (offset > 0) {
			get_data_from_core(
				core_info->phdr[index].p_offset, 
				core_info->phdr[index].p_memsz, 
				coredata->coremem[segindex].data);
		}else{
			assert(0);
		}

		coredata->coremem[segindex].low = core_info->phdr[index].p_vaddr;
		coredata->coremem[segindex].high = core_info->phdr[index].p_vaddr + core_info->phdr[index].p_memsz;

		segindex++;
	}	
	
	coredata->memsegnum = segindex; 


	re_ds.root = NULL;

//take care of registers, including xmm and gs
	threadnum = select_thread(core_info, binary_info);
	if(re_ds.root){
		print_operand(*re_ds.root);
	}

	memcpy(coredata->corereg.regs, 
		core_info->note_info->core_thread.threads_status[threadnum].pr_reg, 
		ELF_NGREG * sizeof(elf_greg_t));

	memcpy(coredata->corereg.xmm_reg, 
		core_info->note_info->core_thread.threads_context[threadnum].xmm_reg, 
		32*(sizeof (long)));

	coredata->corereg.gs_base = 
		core_info->note_info->core_thread.lts[threadnum].lts_info[0].base;

	return coredata;
}

unsigned long load_trace(elf_core_info* core_info, elf_binary_info * binary_info, char *trace_file, x86_insn_t *instlist){

    char line[ADDRESS_SIZE + 2];
    int offset = 0;
    char inst_buf[INST_LEN];
    unsigned long i;
    FILE *file;
    x86_insn_t inst;
    Elf32_Addr address;

    if ((file = fopen(trace_file, "r" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    i = 0; 	

    while (fgets(line, sizeof(line), file) != NULL) {
        // need to check the result of strtoll instead of strncmp
        if (strncmp(line, "[disabled]", 10) == 0) continue;
        if (strncmp(line, "[enabled]", 9) == 0) continue;
        if (strncmp(line, "[resumed]", 9) == 0) continue;

        // strtol return unsigned long.
        // So if input is bigger than 0x80000000, it will return 0x7fffffff
        address = (Elf32_Addr)strtoll(line, NULL, 16);
        offset = get_offset_from_address(core_info, address);

        if (offset == ME_NMAP || offset == ME_NMEM) {
            LOG(stderr, "ERROR: The offset of this pc cannot be obtained\n");
            return -1;
        }

        if (offset == ME_NDUMP) {
            if((get_data_from_specified_file(core_info, binary_info, address, inst_buf, INST_LEN)) < 0)
                return -1;
        }   

        if (offset >= 0)
            get_data_from_core((Elf32_Addr)offset, INST_LEN, inst_buf);
         
        if (disasm_one_inst(inst_buf, INST_LEN, 0, instlist + i) < 0) {
            LOG(stderr, "ERROR: The PC points to an error position\n");
            return -1;
        }
#if 0
	char line1[64];
        x86_format_insn(instlist+i, line1, 64, intel_syntax); 

	printf("%s\n", line1);
#endif

	instlist[i++].addr = address;	
    }
    return i;
}

void destroy_instlist(x86_insn_t * instlist){
	if(instlist)
		free(instlist);
	instlist = NULL;
}

static char *useless_inst[] = {
	"prefetcht0",
	"lfence"
};

#define NUINST (sizeof(useless_inst)/sizeof(char *))

bool verify_useless_inst(x86_insn_t *inst) {
	int i;

	if (!inst) {
		return false;
	}

	for (i = 0; i < NUINST; i++) {
		if (strcmp(inst->mnemonic, useless_inst[i]) == 0)
			return true;
	}
        return false;
}

