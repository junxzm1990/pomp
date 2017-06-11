#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <sysexits.h>
#include <stdint.h>
#include <errno.h>
#include "elf_core.h"
#include "access_memory.h"
#include "reverse_log.h"

#define XMMPOS() 4*sizeof(short) + 6 * sizeof(long) + 32* sizeof(long)

// translate Elf_kind to meaningful output
void print_elf_type(Elf_Kind ek){
    switch (ek){
    case ELF_K_AR:
        LOG(stdout, "DEBUG: Archive\n");
        break;
    case ELF_K_ELF:
        LOG(stdout, "DEBUG: ELF object\n");
        break;
    case ELF_K_NONE:
        LOG(stdout, "DEBUG: Data\n");
        break;
    default:
        LOG(stderr, "DEBUG: Unrecognized\n");
        break;
    }
}

// destroy core_note_info structure inside core_info
int destryp_note_info(core_note_info *note_info){
    if (note_info->core_file.file_info){
    	free(note_info->core_file.file_info);
    	note_info->core_file.file_info = NULL;		
    }
    if (note_info->core_thread.threads_status){
        free(note_info->core_thread.threads_status);
        note_info->core_thread.threads_status = NULL;
    }	
    if (note_info->core_thread.lts){
        int index = 0;
        for (index=0; index<note_info->core_thread.thread_num; index++){
            free(note_info->core_thread.lts[index].lts_info);
            note_info->core_thread.lts[index].lts_info = NULL;
        }
        free(note_info->core_thread.lts);
        note_info->core_thread.lts = NULL;
    }


	//free the memory for XMM registers
    if(note_info->core_thread.threads_context){

	free(note_info->core_thread.threads_context);
	note_info->core_thread.threads_context = NULL;
    }	

    return 0;
}

// destroy elf_core_info structure
int destroy_core_info(elf_core_info *core_info){
    if (core_info && core_info->note_info){
    	destryp_note_info(core_info->note_info);
    }
    if (core_info && core_info->phdr){
    	free(core_info->phdr);
    	core_info->phdr = NULL;
    }
    /*
    if (core_info && core_info->shdr){
    	free(core_info->shdr);
    	core_info->shdr = NULL;
    }
    */
    if (core_info){
    	free(core_info);	
    	core_info = NULL;
    }
    return 0;
}

// process all the note entries
int process_note_info(elf_core_info *core_info, char *note_data, unsigned int size){
    size_t thread_num = 0;
    size_t nt_file_num = 0;

    prstatus_t n_prstatus;
    char *note_start = note_data; 
    char *note_end = note_data + size; 	
    Elf32_Nhdr n_entry;
    int reg_num;

    //check if nt_file exists and count the number of threads in this process
    while (note_data < note_end){
    	memcpy(&n_entry, note_data, sizeof(Elf32_Nhdr));
        note_data += sizeof(Elf32_Nhdr);
        note_data += align_power(n_entry.n_namesz, 2);

    	if(n_entry.n_type == NT_PRSTATUS)
    	    thread_num ++;

    	if(n_entry.n_type == NT_FILE)
    	    memcpy(&nt_file_num, note_data, sizeof(unsigned long));
    	
    	note_data += align_power(n_entry.n_descsz, 2);
    }

    //prepare the core_info memory space
    if ((core_info->note_info = (core_note_info*)malloc(sizeof(core_note_info))) == NULL){
    	return -1;
    }

    //prepare what to fill in the core_info structure

    //prepare the process information
    core_info->note_info->core_process.exist = 0;	

    //prepare the nt file entries
    core_info->note_info->core_file.nt_file_num = 0;
    if (!nt_file_num) 
        core_info ->note_info->core_file.file_info = NULL;
    else 
        if ((core_info->note_info->core_file.file_info = (nt_file_info*)malloc(nt_file_num * sizeof(nt_file_info))) != NULL){
    	    core_info->note_info->core_file.nt_file_num = nt_file_num;
        }
    	
    //prepare the threads entries
    core_info->note_info->core_thread.thread_num = 0;
    if (!thread_num){
    	core_info->note_info->core_thread.threads_status = NULL; 
    }else{
      if((core_info->note_info->core_thread.threads_status = 
    		(prstatus_t *)malloc( thread_num* sizeof(struct elf_prstatus))) != NULL)	
	
	//allocate space for the LTS and XMM registers
    	core_info -> note_info->core_thread.thread_num = thread_num; 
	
      core_info->note_info->core_thread.lts = (nt_lts *)malloc(thread_num * sizeof(nt_lts));
	
	core_info->note_info->core_thread.threads_context = 
	(nt_thread_context * )malloc(thread_num * sizeof(nt_thread_context));
    }
    note_data = note_start; 

    unsigned int thread_index = 0; 

    while (note_data < note_end){
        memcpy(&n_entry, note_data, sizeof(Elf32_Nhdr));
        note_data += sizeof(Elf32_Nhdr);
        note_data += align_power(n_entry.n_namesz, 2);

    	if (n_entry.n_type == NT_PRPSINFO){
    	    core_info->note_info->core_process.exist = 1;
    	    memcpy(&core_info->note_info->core_process.process_info, note_data, sizeof(struct elf_prpsinfo));
    	}



        if (n_entry.n_type == NT_PRSTATUS && core_info -> note_info->core_thread.thread_num > 0){
            memcpy(&core_info->note_info->core_thread.threads_status[thread_index], note_data, sizeof(struct elf_prstatus));
    	    int reg_num = 0;
    	    LOG(stdout, "DEBUG: Info of No.%d thread\n",
                    thread_index + 1);
    	    LOG(stdout, "DEBUG: The number of pending signal is 0x%x\n", 
                    core_info -> note_info->core_thread.threads_status[thread_index].pr_info.si_signo);
    	    thread_index++; 
        }

//ongoing
	if (n_entry.n_type == NT_PRXFPREG){ 
		memcpy(core_info->note_info->core_thread.threads_context[thread_index - 1].xmm_reg, note_data + XMMPOS(), 32 * sizeof(long));	
		int ii; 

		for(ii=0; ii<32; ii+=4)
			LOG(stdout, "DEBUG: XMM[%d] 0x%lx 0x%lx 0x%lx 0x%lx\n", ii/4, 
				core_info->note_info->core_thread.threads_context[thread_index - 1].xmm_reg[ii],	
				core_info->note_info->core_thread.threads_context[thread_index - 1].xmm_reg[ii+1],	
				core_info->note_info->core_thread.threads_context[thread_index - 1].xmm_reg[ii+2],	
				core_info->note_info->core_thread.threads_context[thread_index - 1].xmm_reg[ii+3]);	
	}
//end ongoing


        if (n_entry.n_type == NT_386_TLS){
            size_t lts_num = n_entry.n_descsz / 0x10;
            core_info->note_info->core_thread.lts[thread_index-1].lts_info = malloc(n_entry.n_descsz);
            memcpy(core_info->note_info->core_thread.lts[thread_index-1].lts_info, note_data, n_entry.n_descsz);
            int lts_index = 0;
            for (lts_index=0;lts_index<lts_num;lts_index++){
                nt_lts_info temp = core_info->note_info->core_thread.lts[thread_index-1].lts_info[lts_index]; 
                LOG(stdout, "DEBUG: TLS Entry - index:%d, base: 0x%x, limit: 0x%x, flags: 0x%x\n", temp.index, temp.base, temp.length, temp.flag);
            }
        }

        if (n_entry.n_type == NT_FILE && core_info->note_info->core_file.nt_file_num >0 ){
            unsigned int i;
            unsigned int index = 0;
            unsigned int fn=0, page_size = 0;
            unsigned int start, end, pos;

            memcpy(&fn, note_data + index, sizeof(unsigned int));
    	    index += sizeof(unsigned int);
    	    memcpy(&page_size, note_data + index, sizeof(unsigned int));
            index += sizeof(unsigned int);

            for (i=0; i<fn; i++){
                memcpy(&start, note_data + index, sizeof(unsigned int));
                index += 4; // 32bit
                memcpy(&end, note_data + index, sizeof(unsigned int));
                index += 4; // 32bit
                memcpy(&pos, note_data + index, sizeof(unsigned int));
                index += 4; // 32bit
    			
    		    core_info ->note_info -> core_file.file_info[i].start = start;
    		    core_info ->note_info -> core_file.file_info[i].end = end;
    		    core_info ->note_info -> core_file.file_info[i].pos = pos;
            }
            for (i=0; i<fn; i++){
    	        strncpy(core_info ->note_info -> core_file.file_info[i].name, note_data + index, FILE_NAME_SIZE);
                index += strlen(note_data + index) + 1;
            }
    	    for (i=0; i<fn; i++) {
                LOG(stdout, "DEBUG: One mapped file name is %s.\n", 
                    core_info ->note_info -> core_file.file_info[i].name);
                LOG(stdout, "DEBUG: It starts 0x%x, end at 0x%x, position 0x%x\n",
                    core_info ->note_info -> core_file.file_info[i].start,
                    core_info ->note_info -> core_file.file_info[i].end,
                    core_info ->note_info -> core_file.file_info[i].pos);
            }
        }
        note_data += align_power(n_entry.n_descsz, 2);
    }
    return 0;
}

// process note segment in program header table
int process_note_segment(Elf* elf, elf_core_info* core_info){
    unsigned int i; 
    unsigned long start, size; 
    size_t phdr_num = 0; 
    GElf_Phdr phdr; 

    if (elf_getphdrnum(elf, &phdr_num) != 0){
         LOG(stderr, "Cannot get the number of program header %s\n", elf_errmsg(-1));
         return -1;
    }

    for (i=0; i<phdr_num; i++){
        if (gelf_getphdr(elf, i, &phdr) != &phdr){
    		LOG(stderr, "Cannot get the number of program header %s\n", elf_errmsg(-1)); 
    	    return -1;
        }

        if (phdr.p_type == PT_NOTE){
    	    start = phdr.p_offset;
            size = phdr.p_filesz;
    		char * note_data = (char*)malloc(size);
    		if (!note_data){
    		    LOG(stderr, "Error when allocating new memory %s\n", strerror(errno));
    			return -1;
    		}
    		if (get_data_from_core(start, size, note_data) < -1){
      		    LOG(stderr, "Error when reading contents from the core file\n");
    			free(note_data);
    			return -1; 
    		}
    		process_note_info(core_info, note_data, size);
    		free(note_data); //please make sure no memory disclosure here
    		break;

        }
    }
    return 0; 
} 

// get all the segments in the core dump
int process_segment(Elf* elf, elf_core_info* core_info){
    size_t phdr_num = 0;
    GElf_Phdr phdr;
    unsigned int i;
    
    //get the number of program headers
    if (elf_getphdrnum(elf , &phdr_num) != 0){
    	LOG(stderr, "Cannot get the number of program header %s\n", elf_errmsg(-1)); 
    	return -1;
    }
    LOG(stdout, "DEBUG: The number of segment in the code file is %d\n", phdr_num);
    core_info->phdr_num = phdr_num;

    //store the headers into newly allocated memory space
    core_info->phdr = NULL;	
    if ((core_info->phdr = (GElf_Phdr*)malloc(phdr_num * sizeof(GElf_Phdr))) == NULL){
        LOG(stderr, "Cannot allocate memory for program header\n");
    	return -1;
    }
    memset(core_info->phdr, 0, phdr_num * sizeof(GElf_Phdr));	
    for (i=0; i< phdr_num; i++){
        if (gelf_getphdr(elf, i, &phdr) != &phdr){
    		LOG(stderr, "Cannot get program header %s\n", elf_errmsg(-1));			
    		return -1;
        }
    	memcpy(&core_info->phdr[i], &phdr, sizeof(GElf_Phdr));
    }
    return 0;
}
/*
int process_section(Elf *elf, elf_core_info *core_info){
    size_t shdr_num = 0;
    Elf_Scn *scn;
    GElf_Shdr shdr;
    unsigned int i;

    scn = NULL;
    // get the number of section headers
    if (elf_getshdrnum(elf, &shdr_num) != 0){
    	LOG(stderr, "Cannot get the number of section header %s\n", elf_errmsg(-1)); 
    	return -1;
    }
    LOG(stdout, "DEBUG: The number of section in the code file is %d\n", shdr_num);

    //store the headers into newly allocated memory space
    core_info->shdr = NULL;
    if ((core_info->shdr = (GElf_Shdr*)malloc(shdr_num * sizeof(GElf_Shdr))) == NULL){
        LOG(stderr, "Cannot allocate memory for section header\n");
    	return -1;
    }
    memset(core_info->shdr, 0, shdr_num * sizeof(GElf_Shdr));	
    i = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if(gelf_getshdr(scn, &shdr) != &shdr)
    		LOG(stderr, "Cannot get section header %s\n", elf_errmsg(-1));			
    	memcpy(&core_info->shdr[i++],&shdr, sizeof(GElf_Shdr));
    }
}
*/
elf_core_info* parse_core(char * core_path){
    int fd;
    Elf* elf;
    elf_core_info* core_info = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE){
    	LOG(stderr, "Not Compitable version of ELF core file\n");
    	return NULL;
    }

    if ((fd = open(core_path, O_RDONLY, 0)) < 0){
        LOG(stderr, "Error When Open ELF core file: %s\n", strerror(errno));
    	return NULL;
    }
    
     if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL){
    	LOG(stderr, "Error When Initilize the ELF object\n");	
    	close(fd);
    	return NULL;
     } 
    print_elf_type(elf_kind(elf));
    core_info = (elf_core_info*)malloc(sizeof(elf_core_info));

    if (core_info == NULL){
    	LOG(stderr, "Error When Memory Allocation\n");
    	elf_end(elf);
        close(fd);
        return NULL;
    }	

    memset(core_info, 0, sizeof(elf_core_info));
    core_info->phdr = NULL;
    core_info->note_info = NULL;
    LOG(stdout, "STATE: Parsing Core File: %s\n", core_path);

    if (process_segment(elf, core_info) < 0){
        LOG(stderr, "the segments are not correctly parsed\n");
    	elf_end(elf);
        close(fd);
    	destroy_core_info(core_info);	
    	return NULL;
    }
/*    
    if (process_section(elf, core_info) < 0){
        LOG(stderr, "the sections are not correctly parsed\n");
    	elf_end(elf);
        close(fd);
    	destroy_core_info(core_info);	
    	return NULL;
    }
*/
    process_note_segment(elf, core_info);

    elf_end(elf); 
    close(fd);
    return core_info;
}
