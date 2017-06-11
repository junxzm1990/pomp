#ifndef __COMMON__
#define __COMMON__

#define align_power(addr,power) \
(addr + (1 << power) - 1) & (-(1 << power))

#define FILE_NAME_SIZE 256
#define ADDRESS_SIZE 32
#define INST_LEN 64

#define BYTE_SIZE 8
#define WORD_SIZE 16
#define DWORD_SIZE 32
#define ADDR_SIZE_IN_BYTE (ADDRESS_SIZE/BYTE_SIZE)

#define ME_NMAP -1
#define ME_NMEM -2
#define ME_NDUMP -3 

#endif
