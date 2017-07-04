#include <stdio.h>
#include <string.h>
#include "reverse_log.h"

unsigned long countvalidaddress(char *filename){
    char line[80];
    FILE *file;
    if ((file = fopen(filename, "r")) == NULL) {
        LOG(stderr, "ERROR: open error\n");
        return -1;
    }
    unsigned long linenum = 0;
    while (fgets(line, sizeof line, file) != NULL) {
        if ((strncmp(line, "[disabled]", 10) == 0)) continue;
        if ((strncmp(line, "[enabled]", 9) == 0)) continue;
        if ((strncmp(line, "[resumed]", 9) == 0)) continue;
        linenum++;
    }

    LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
    return linenum;
}


#ifdef DATA_LOGGED

//count the number of instructions that have valid data logging
unsigned long countvalidlog(char * filename){
	char line[256];
	FILE *file;
	unsigned long linenum;

	if((file = fopen(filename, "r")) == NULL){
		LOG(stderr, "ERROR: cannot open file containing data log\n");
		return -1;
	}

	linenum = 0;
	while(fgets(line, sizeof(line), file) != NULL){
		linenum++;
	}

	LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
	return linenum;
}
#endif

