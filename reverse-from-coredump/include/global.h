#ifndef __GLOBAL__
#define __GLOBAL__

#include <libdis.h>
#include "elf_core.h"
#include "elf_binary.h"

extern char *core_path;
extern char *bin_path;
extern char *inst_path;

#ifdef DATA_LOGGED
extern char* log_path;
extern char* xmm_path;
#endif

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

#ifdef DATA_LOGGED
void set_log_path(char * path);
char* get_log_path(void);
unsigned long countvalidlog(char *filename);
void set_xmm_path(char * path);
char* get_xmm_path(void);
#endif

#ifdef BIN_ALIAS
extern char * sum_path;
void set_sum_path(char* path);
#endif

#endif
