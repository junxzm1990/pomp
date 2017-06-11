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
