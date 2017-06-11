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
#if 0
// Load coredump and external library information
int load_binlib(char *argv[]){
    set_core_path(argv[1]);
    set_bin_path(argv[2]);
    set_inst_path(argv[3]);

    elf_core_info *core_info_local = parse_core(argv[1]); 

    if (!core_info_local) {
        LOG(stderr,"ERROR: The core file is not parsed correctly");
        return 0;
    }
    set_core_info(core_info_local);

    elf_binary_info *binary_info_local = parse_binary(core_info_local); 

    if (!binary_info_local) {
        LOG(stderr,"ERROR: The binary file is not parsed correctly");
        return 0;
    }
    set_bin_info(binary_info_local);
    return 1;
}




Elf32_Addr get_address_from_expression(appinst_t *appinst, x86_ea_t expression){
    // type check here
    Elf32_Addr address = 0;
    unsigned int reg;
    x86_ea_t temp = expression;
    LOG(stdout, "DEBUG: ----start get address from expression----\n");
    LOG(stdout, "DEBUG: scale = %d\n", temp.scale);
    LOG(stdout, "DEBUG: disp: %d, disp_sign: %d, disp_size: %d\n", temp.disp, temp.disp_sign, temp.disp_size);
    if (temp.index.id != 0) {
        reg = get_value_from_reg(appinst, temp.index);
        address += reg * temp.scale;
        LOG(stdout, "DEBUG: index name = %s\n", temp.index.name);
    }
    if (temp.base.id != 0) {
        reg = get_value_from_reg(appinst, temp.base);
        address += reg;
        LOG(stdout, "DEBUG: base name = %s\n", temp.base.name);
    }
    address += temp.disp;
    LOG(stdout, "DEBUG: Final Address is 0x%x\n", address);
    LOG(stdout, "DEBUG: ----end get address from expression----\n");
    return address;
}

// get address from op_offset (gs:0x0C)
Elf32_Addr get_address_from_offset(x86_op_t *opd){
    LOG(stdout, "DEBUG: ----start get address from offset----\n");
    Elf32_Addr address = opd->data.offset;
    LOG(stdout, "DEBUG: offset = 0x%x\n", opd->data.offset);

    assert(opd->flags & op_gs_seg);
    if (opd->flags & op_gs_seg) {
        address += get_gs_base_address(get_core_info());
        LOG(stdout, "DEBUG: prefix segment is gs\n");
    }
    LOG(stdout, "DEBUG: Final Address is 0x%x\n", address);
    LOG(stdout, "DEBUG: ----end   get address from offset----\n");
    return address;
}

/*
// malloc new memory for appphdr_data, 
int malloc_new_memory(appphdr_data_t *mem){
    GElf_Phdr temp = core_info->phdr[mem->index];
    char * tempp;
    if ((tempp = malloc(temp.p_memsz)) == NULL){        
        LOG(stderr, "DEBUG: Malloc error\n");
        return -1;
    }

    memcpy(tempp, mem->data, temp.p_memsz);
    mem->data = tempp;
    tempp = NULL;
    return 0;
}*/

// get index in appinst->data.mem
int index_in_appdata(appinst_t *appinst, Elf32_Addr address){
    int i, num = appinst->data.effective_phdr;
    appphdr_data_t *memory = appinst->data.mem; 
    for (i = 0; i < num; i++) {
        GElf_Phdr temp = core_info->phdr[memory[i].index];
        if (address >= temp.p_vaddr && address < temp.p_vaddr+temp.p_memsz) {
            break;
        }
    }
    if (i >= num) {
        LOG(stderr, "ERROR: Address is not in the memory\n");
        assert(0);
    } else {
        return i;
    }
}

// Update operands with inverse_function function pointer
void update_operands(appinst_t *appinst, inverse_function *inverse){
    x86_insn_t *inst = &appinst->inst;
    x86_op_t *opd1 = x86_get_dest_operand(inst);
    x86_op_t *opd2 = x86_get_src_operand(inst);
    x86_op_t *opd3 = x86_get_imm_operand(inst);
    switch (inst->type) {
    // no explicit operand, only use  
    case insn_leave:
        opd1 = &inst->operands->op;
        opd2 = &inst->operands->next->op;
        break;
    }

    inverse(appinst, opd1, opd2, opd3);
}

// Get result with forward_function function pointer
unsigned int get_result_from_inst(appinst_t *appinst){
    x86_insn_t *inst = &(appinst->inst);
    x86_op_t *opd1 = x86_get_dest_operand(inst);
    x86_op_t *opd2 = x86_get_src_operand(inst);
    x86_op_t *opd3 = x86_get_imm_operand(inst);

    LOG(stdout, "DEBUG: Get result from Instruction : ");
    print_assembly(inst);

    unsigned int value;
    switch (inst->type) {
    case insn_add:
        value = forward_add(appinst, opd1, opd2, opd3);
        break;
    case insn_sub:
        value = forward_sub(appinst, opd1, opd2, opd3);
        break;
    case insn_mov:
        value = forward_mov(appinst, opd1, opd2, opd3);
        break;
    case insn_xchgcc:
        value = forward_xchgcc(appinst, opd1, opd2, opd3);
        break;
    case insn_push:
        value = forward_push(appinst, opd1, opd2, opd3);
        break;
    case insn_pop:
        value = forward_pop(appinst, opd1, opd2, opd3);
        break;
    case insn_rol:
        value = forward_rol(appinst, opd1, opd2, opd3);
        break;
    case insn_ror:
        value = forward_ror(appinst, opd1, opd2, opd3);
        break;
    case insn_xor:
        value = forward_xor(appinst, opd1, opd2, opd3);
        break;
    case insn_and:
        value = forward_and(appinst, opd1, opd2, opd3);
        break;
    case insn_test:
        value = forward_test(appinst, opd1, opd2, opd3);
        break;
    case insn_shr:
        value = forward_shr(appinst, opd1, opd2, opd3);
        break;
    default:
        LOG(stderr, "ERROR: No analysis for instruction type 0x%x\n", inst->type);
        break;
    }
    return value;
}

unsigned char *get_pointer_from_address(appinst_t *appinst, Elf32_Addr address){
    // assert when I can not find this address
    int effid = index_in_appdata(appinst, address); 
    int id = appinst->data.mem[effid].index;
    int offset = address - core_info->phdr[id].p_vaddr;
    unsigned char *tempp = appinst->data.mem[effid].data + offset;
    return tempp;
}

unsigned int get_value_from_address(appinst_t *appinst, Elf32_Addr address, enum x86_op_datatype datatype){
    unsigned int value = 0;
    unsigned char *p = get_pointer_from_address(appinst, address);

    if (datatype == op_byte) {
        value += (*p);
    } else if (datatype == op_word) {
        value += (*((unsigned short *)p));
    } else if (datatype == op_dword) {
        value += (*((unsigned int *)p));
    }
    return value;
}

unsigned int get_value_from_expression(appinst_t *appinst, x86_op_t *opd){
    unsigned int value = 0;
    if (opd->type != op_expression) {
        LOG(stderr, "ERROR: opd is not expression\n");
    }
    Elf32_Addr address = get_address_from_expression(appinst, opd->data.expression);
    if (opd->flags & op_gs_seg) {
        address += get_gs_base_address(get_core_info());
    }
    unsigned char *p = get_pointer_from_address(appinst, address);

    if (opd->datatype == op_byte) {
        value += (*p);
    } else if (opd->datatype == op_word) {
        value += (*((unsigned short *)p));
    } else if (opd->datatype == op_dword) {
        value += (*((unsigned int *)p));
    }
    return value;
}

void set_value_to_expression(appinst_t *appinst, x86_op_t *opd, unsigned int value){
    if (opd->type != op_expression) {
        LOG(stderr, "ERROR: opd is not expression\n");
    }
    Elf32_Addr address = get_address_from_expression(appinst, opd->data.expression);
    LOG(stdout, "DEBUG: set value 0x%x to address 0x%x\n", value, address);
    int effid = index_in_appdata(appinst, address);
    unsigned char *p = get_pointer_from_address(appinst, address);

    if (opd->datatype == op_byte) {
        (*p) = (char) value;
    } else if (opd->datatype == op_word) {
        unsigned short *tp = (unsigned short *)p;
        (*tp) = (unsigned short) value;
    } else if (opd->datatype == op_dword) {
        unsigned int *tp = (unsigned int *)p;
        (*tp) = value;
    }
}

unsigned int get_value_from_immediate(appinst_t *appinst, x86_op_t *opd){
    if (opd->type != op_immediate) {
        LOG(stderr, "ERROR: opd is not immediate\n");
    }
    unsigned int value = 0;
    if (opd->datatype == op_byte) {
        value += opd->data.sbyte;
    } else if (opd->datatype == op_word) {
        value += opd->data.sword;
    } else if (opd->datatype == op_dword) {
        value += opd->data.sdword;
    }
    return value;
}

// get value from op_offset
unsigned int get_value_from_offset(appinst_t *appinst, x86_op_t *opd){
    if (opd->type != op_offset) {
        LOG(stderr, "ERROR: opd is not offset like gs:0x0C\n");
    }
    unsigned int value = 0;
    Elf32_Addr address = get_address_from_offset(opd);
    unsigned char *p = get_pointer_from_address(appinst, address);

    if (opd->datatype == op_byte) {
        value += (*p);
    } else if (opd->datatype == op_word) {
        value += (*((unsigned short *)p));
    } else if (opd->datatype == op_dword) {
        value += (*((unsigned int *)p));
    }
    return value;
}

unsigned int get_value_from_opd(appinst_t *appinst, x86_op_t *opd){
    unsigned int value = 0;
    switch (opd->type) {
    case op_register:
        value = get_value_from_reg(appinst, opd->data.reg);
        break;
    case op_expression:
        value = get_value_from_expression(appinst, opd);
        break;
    case op_immediate:
        value = get_value_from_immediate(appinst, opd);
        break;
    case op_offset:
        value = get_value_from_offset(appinst, opd);
        break;
    }
    return value;
}

void set_value_to_opd(appinst_t *appinst, x86_op_t *opd, unsigned int value){
    switch (opd->type) {
    case op_register:
        set_value_to_reg(appinst, opd->data.reg, value);
        break;
    case op_expression:
        set_value_to_expression(appinst, opd, value);
        break;
    case op_offset:
        assert(0);
        break;
    }
}

unsigned int *check_exist_in_coredump(appdata_t *appdata, unsigned int value, unsigned char byte_num){
    LOG(stdout, "DEBUG: ---start check exists of one value in coredump\n");
    int i, j, index, length, count;
    Elf32_Addr base;
    unsigned char *p;
    count = 0;
    for (i=0;i<appdata->effective_phdr;i++) {
        length = core_info->phdr[appdata->mem[i].index].p_memsz;
        p = appdata->mem[i].data;
        if (appdata->mem[i].flags & PF_W) {
            for (j=0;j<length+1-byte_num;j++) {
                if (byte_num == 1){
                    unsigned char *temp = p+j;
                    if ((unsigned int)(*temp) == value) count++;
                } else if (byte_num == 2) {
                    unsigned short *temp = (unsigned short *)(p+j);
                    if ((unsigned int)(*temp) == value) count++;
                } else if (byte_num == 4) {
                    unsigned int *temp = (unsigned int *)(p+j);
                    if (*temp == value) count++;
                } else {
                    LOG(stderr, "ERROR: No such length analysis");
                    assert(0);
                }
            }
        }
    }
    // add all the unresolved memory write, their beforevalues may be the parameter - value
    appdefheadlist_t *temp;
    list_for_each_entry_reverse (temp, &urmdefhead.list, list) {
        if (temp->opd.type == op_expression) 
            if ((temp->addr_status) && (!(temp->status & before_known)))
                count++;
    }
    unsigned int *result = malloc((count+1) * sizeof(unsigned int *));
    if (result == NULL) {
        LOG(stderr, "ERROR: malloc error in prepare_coredump\n");
        return NULL;
    }
    LOG(stdout, "DEBUG: address count = %d\n", count);
    result[0] = count; // Store count in the first place
    count = 1;
    for (i=0;i<appdata->effective_phdr;i++) {
        index = appdata->mem[i].index;
        length = core_info->phdr[index].p_memsz;
        base = core_info->phdr[index].p_vaddr;
        p = appdata->mem[i].data;
        LOG(stdout, "DEBUG: base: 0x%x, length: 0x%x\n", base, length);
        if (appdata->mem[i].flags & PF_W) {
            for (j=0;j<length+1-byte_num;j++) {
                if (byte_num == 1) {
                    unsigned char *temp = p+j;
                    if ((unsigned int)(*temp) == value) {
                        LOG(stdout, "DEBUG: (byte)  find one address %x in coredump\n", base + j);
                        result[count++] = (unsigned int)(base+j);
                    }
                } else if (byte_num == 2) {
                    unsigned short *temp = (unsigned short *)(p+j);
                    if ((unsigned int)(*temp) == value) {
                        LOG(stdout, "DEBUG: (short) find one address %x in coredump\n", base + j);
                        result[count++] = (unsigned int)(base+j);
                    }
                } else if (byte_num == 4) {
                    unsigned int *temp = (unsigned int *)(p+j);
                    if (*temp == value) {
                        LOG(stdout, "DEBUG: (int)   find one address %x in coredump\n", base + j);
                        result[count++] = (unsigned int)(base+j);
                    }
                }
            }
        }
    }
    list_for_each_entry_reverse (temp, &urmdefhead.list, list) {
        if (temp->opd.type == op_expression) 
            if ((temp->addr_status) && (!(temp->status & before_known))){
                LOG(stdout, "DEBUG: find one unresolved memory write at %x\n", temp->address);
                result[count++] = temp->address;
            }
    }
    LOG(stdout, "DEBUG: ---end   check exists of one value in coredump\n");
    return result;
}

// get gs selector base address from core_info structure
Elf32_Addr get_gs_base_address(elf_core_info *core_info){
    int n = core_info->note_info->core_thread.crash_thread;
    // only the first entry is valid. Obtain its length.
    return core_info->note_info->core_thread.lts[n].lts_info[0].base;
}

// 1 : unknown; 0: known
int check_esp_is_unknown(appinst_t *appinst) {
    int flag = 0;
    x86_reg_t tempreg;
    x86_reg_t esp;
    memset(&esp, 0, sizeof(x86_reg_t));
    x86_reg_from_id(x86_sp_reg(), &esp);
    appstop_t *stop = NULL;
    list_for_each_entry(stop, &appinst->stop.list, list) {
        if (x86_opd_is_register(&stop->unknown) && (compare_regs(stop->unknown.data.reg, esp))) {
            flag = 1;
            break;
        }
    }
    return flag;
}

// 1 : unknown; 0: known
int check_reg_is_unknown(appdefheadlist_t *defhead, x86_reg_t *reg) {
    int flag = 0;
    appdefheadlist_t *regdefentry = find_reg_in_deflist(defhead, reg);
    if ((regdefentry != NULL) && (!(regdefentry->status & before_known))) {
        flag = 1;
    } else {
        flag = 0;
    }
    return flag;
}

// return the corresponding esp value which has the return address
Elf32_Addr search_retaddr_in_segment(appinst_t *appinst, Elf32_Addr retaddr){
    x86_reg_t ebp;
    memset(&ebp, 0, sizeof(x86_reg_t));
    x86_reg_from_id(get_ebp_id(), &ebp);
    Elf32_Addr ebpvalue = get_value_from_reg(appinst, ebp);
    elf_core_info *localcore_info = get_core_info();
    int index = address_segment(localcore_info, ebpvalue);
    if (index == -1) assert(0);
    Elf32_Addr startaddr = localcore_info->phdr[index].p_vaddr;
    Elf32_Addr tempaddr;
    unsigned int value;
    for (tempaddr = startaddr; tempaddr < ebpvalue; tempaddr++) {
        // eip address length
        value = get_value_from_address(appinst, tempaddr, op_dword);
        if (value == retaddr) {
            LOG(stdout, "RESOLVE_ESP: Already find the corresponding esp\n");
            break;
        }
    }
    return tempaddr;
}
#endif
