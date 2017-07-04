#include "global.h"
#include "ia32_reg.h" // obtain from libdisasm
#include "reverse_exe.h"
#include "inst_opd.h"
#include "reverse_log.h"
#include "insthandler.h"


// translate from the id of register in the libdisasm to the index in sys/reg.h 
// only applied to base register
int get_index_from_x86_reg_t(x86_reg_t reg){
    int index = 0;
    switch(reg.id) {
        case get_eax_id():
        case get_ax_id():
        case get_ah_id():
        case get_al_id():
            index = EAX;
            break;
        case get_ebx_id():
        case get_bx_id():
        case get_bh_id():
        case get_bl_id():
            index = EBX;
            break;
        case get_ecx_id():
        case get_cx_id():
        case get_ch_id():
        case get_cl_id():
            index = ECX;
            break;
        case get_edx_id():
        case get_dx_id():
        case get_dh_id():
        case get_dl_id():
            index = EDX;
            break;
        case get_esi_id():
        case get_si_id():
            index = ESI;
            break;
        case get_edi_id():
        case get_di_id():
            index = EDI;
            break;
        case get_ebp_id():
        case get_bp_id():
            index = EBP;
            break;
        case get_esp_id():
        case get_sp_id():
            index = UESP;
            break;
        case get_eflags_id():
            index = EFL;
            break;
        case get_eip_id():
            index = EIP;
            break;
        default:
            LOG(stderr, "No case for such register : %s\n", reg.name);
	    index = -1;
            break;
    }
    return index;
}


void get_value_from_xmm_reg(x86_reg_t reg, valset_u *value){
	unsigned int index = reg.id - REG_SIMD_OFFSET;
	memcpy(&value->dqword, re_ds.coredata->corereg.xmm_reg + index * 4, 4 * sizeof(long));
}


// get the value of register from x86_reg_t
unsigned int get_value_from_gen_reg(x86_reg_t reg){

	int index = get_index_from_x86_reg_t(reg);
	if (index == -1) {
		assert(0);
    	}
	unsigned int value = re_ds.coredata->corereg.regs[index];

	return value;
}


int get_regval_from_coredump(x86_reg_t reg, valset_u *value){

	if ((reg.type&reg_gen)||(reg.type&reg_sp)||(reg.type&reg_fp)||(reg.type&reg_pc)) {
		unsigned int gen_value = get_value_from_gen_reg(reg);
		switch (reg.size) {
		case 1:
        		if((strcmp(reg.name, "ah") == 0)||
			   (strcmp(reg.name, "bh") == 0)||
			   (strcmp(reg.name, "ch") == 0)||
			   (strcmp(reg.name, "dh") == 0) ) {
            			value->byte = gen_value & 0x0000ff00;
			} else {
				value->byte = gen_value & 0x000000ff;
			}
			break;
		case 2:
			value->word = gen_value & 0x0000ffff;
			break;
		case 4:
			value->dword = gen_value;
			break;
		}
	} else if (reg.type & reg_simd) {
		get_value_from_xmm_reg(reg, value);
	}
	return GET_VALUE_OK;
}


static int index_of_memseg(Elf32_Addr address) {
	int index = 0;
	for (index = 0;index <re_ds.coredata->memsegnum;index++) {
		if ((address >= re_ds.coredata->coremem[index].low) 
			&& (address < re_ds.coredata->coremem[index].high)){
			return index;
		}
	}
	return -1;
}


static void *get_pointer_from_coremem(Elf32_Addr address) {

	int index = index_of_memseg(address);

	if (index == -1) {
		LOG(stdout, "LOG: No such address\n");
		return NULL;
	} else {
		void *dp = re_ds.coredata->coremem[index].data;
		dp += address - re_ds.coredata->coremem[index].low;
		return dp;
	}
}


int get_memval_from_coredump(re_list_t *entry, valset_u *value) {
	Elf32_Addr address;
	x86_op_t *opd;
	void *p;

	switch (entry->node_type) {
		case DefNode:
			address = CAST2_DEF(entry->node)->address;
			opd = CAST2_DEF(entry->node)->operand;
			break;
		case UseNode:
			address = CAST2_USE(entry->node)->address;
			opd = CAST2_USE(entry->node)->operand;
			break;
		default:
			LOG(stderr, "LOG: Error node type\n");
			assert(0);
			break;
	}
	
	p = get_pointer_from_coremem(address);
	
	if (p == NULL) {
		LOG(stdout, "LOG: Error address\n");
		return BAD_ADDRESS;
	} 

	if (opd->datatype == op_byte) {
		value->byte = (*((unsigned char *)p));
	} else if (opd->datatype == op_word) {
		value->word = (*((unsigned short *)p));
	} else if (opd->datatype == op_dword) {
		value->dword = (*((unsigned int *)p));
	} else {
		LOG(stderr, "LOG: Error data type\n");
		assert(0);
	}
	return GET_VALUE_OK;
}


int get_value_from_coredump(re_list_t *entry, valset_u *value) {
	x86_op_t *opd;
	int retval;
	switch (entry->node_type) {
	case DefNode:
		opd = CAST2_DEF(entry->node)->operand;
		switch (opd->type) {
		case op_register:
			retval = get_regval_from_coredump(opd->data.reg, value);
			break;
		case op_expression:
			retval = get_memval_from_coredump(entry, value);
			break;
		case op_offset:
			CAST2_DEF(entry->node)->address = re_ds.coredata->corereg.gs_base + opd->data.offset;
			retval = get_memval_from_coredump(entry, value);
			break;
		default:
			LOG(stderr, "LOG: No such opd type %d for define node\n", opd->type);
			assert(0);
		}

		break;
	case UseNode:
		opd = CAST2_USE(entry->node)->operand;
		switch (CAST2_USE(entry->node)->usetype) {
		case Opd:
			switch (opd->type) {
			case op_register:
				retval = get_regval_from_coredump(opd->data.reg, value);
				break;
			case op_expression:
				retval = get_memval_from_coredump(entry, value);
				break;
			case op_offset:
				CAST2_USE(entry->node)->address = re_ds.coredata->corereg.gs_base + opd->data.offset;
				retval = get_memval_from_coredump(entry, value);
				break;
			default:
				LOG(stderr, "LOG: No such opd type %d for use node\n", opd->type);
				assert(0);
			}
			break;
		case Base:
			// reg value
			retval = get_regval_from_coredump(opd->data.expression.base, value);	
			break;		
		case Index:
			// reg value
			retval = get_regval_from_coredump(opd->data.expression.index, value);	
			break;		
		}
		break;
	default:
		LOG(stderr, "No such node type %d\n", entry->node_type);
		assert(0);
	}
	return retval;
}


// get immediate value from operand
int get_immediate_from_opd(x86_op_t *opd, valset_u *value) {
	if (opd->type != op_immediate) {
		LOG(stderr, "ERROR: opd is not immediate\n");
		assert(0);
	}
	if (opd->datatype == op_byte) {
		value->byte = opd->data.byte;
	} else if (opd->datatype == op_word) {
		value->word = opd->data.word;
	} else if (opd->datatype == op_dword) {
		value->dword = opd->data.dword;
	}
	return GET_VALUE_OK;
}

unsigned search_address_of_value(valset_u vt, enum x86_op_datatype datatype){

	int index;
	size_t size; 
	unsigned address; 
	void *start;
	memseg_t *tmem; 
	
	address = 0;	
	size = translate_datatype_to_byte(datatype);

	//search each of the segments 
	for(index = 0; index < re_ds.coredata->memsegnum; index++){

		tmem = re_ds.coredata->coremem + index; 		
		for(start = tmem->data; start <= (tmem->data + tmem->high - tmem->low - size); start++){

			if(!memcmp(start, &vt, size)){

				if(address)
					return 0;		
				address = (unsigned)(tmem->low + (start - tmem->data));

			}
		}	
	}

	if(!address){
		return 0;
	}

	return address; 
} 



void search_value_from_coredump(valset_u searchvalue, enum x86_op_datatype datatype, unsigned **dp, unsigned *num) {
	int index;
	void *value;
	memseg_t *temp;

	size_t size = translate_datatype_to_byte(datatype);
	*num = 0;
	// skip first segment : pt_node
	for (index = 0; index<re_ds.coredata->memsegnum; index++) {
		temp = re_ds.coredata->coremem + index;
		for (value=temp->data; value<temp->data+temp->high-temp->low-size+1; value++) {
			switch (datatype) {
				case op_byte:
					assert(0);
					break;
				case op_word:
					assert(0);
					break;
				case op_dword:
					if (*((unsigned int *)value) == searchvalue.dword) {
						(*num)++;
					}
					break;
				default:
					assert("No such datatype analysis" && 0);
			}
		}
	}
	LOG(stdout, "LOG: num = %d\n", *num);
	if (num == 0) {
		LOG(stderr, "LOG: No such value in the coredump\n");
		(*dp) = NULL;
		assert(0);
		return;
	} else {
		(*dp) = (unsigned *)malloc((*num)*sizeof(unsigned *));
	}
	
	int n = 0;
	// skip first segment : pt_node
	for (index = 0; index<re_ds.coredata->memsegnum; index++) {
		temp = re_ds.coredata->coremem + index;
		for (value=temp->data; value<temp->data+temp->high-temp->low-size+1; value++) {
			switch (datatype) {
				case op_byte:
					assert(0);
					break;
				case op_word:
					assert(0);
					break;
				case op_dword:
					if (*((unsigned *)value) == searchvalue.dword) {
						(*dp)[n++] = temp->low + (unsigned)(value - temp->data);
					}
					break;
				default:
					assert("No such datatype analysis" && 0);
			}
		}
	}
	assert(n == *num);
}


x86_op_t * x86_implicit_operand_1st( x86_insn_t *inst ) {
	x86_oplist_t *temp;
	int count = 0;
	for(temp = inst->operands;temp; temp = temp->next, count++) {
		if (count == inst->explicit_count) {
			return &temp->op;
		}
	}
	return NULL;
}


x86_op_t * x86_implicit_operand_2nd( x86_insn_t *inst ) {
	x86_oplist_t *temp;
	int count = 0;
	for(temp = inst->operands;temp; temp = temp->next, count++) {
		if (count == inst->explicit_count) {
			if (temp->next) {
				return &temp->next->op;
			} else {
				return NULL;
			}
		}
	}
	return NULL;
}


x86_op_t * x86_implicit_operand_3rd( x86_insn_t *inst ) {
	x86_oplist_t *temp;
	int count = 0;
	for(temp = inst->operands;temp; temp = temp->next, count++) {
		if (count == inst->explicit_count) {
			if (temp->next) {
				if (temp->next->next) {
					return &temp->next->next->op;
				} else {
					return NULL;
				}
			} else {
				return NULL;
			}
		}
	}
	return NULL;
}

static void x86_implicit_oplist_append(x86_insn_t *insn, x86_oplist_t *op) {
	x86_oplist_t *list;

	if (! insn ) {	
		return;
	}

	list = insn->operands;

	/* get to end of list */
	for ( ; list->next; list = list->next ) 
		;

	insn->operand_count = insn->operand_count + 1;
	list->next = op;

	return;
}

x86_op_t *x86_implicit_operand_new(x86_insn_t *insn) {
	x86_oplist_t *op;

	if (!insn) {	
		return NULL;
	}
	op = (x86_oplist_t *)malloc(sizeof(x86_oplist_t));
	memset(op, 0, sizeof(x86_oplist_t));
	op->op.insn = insn;
	x86_implicit_oplist_append( insn, op );
	return( &(op->op) );
}

x86_op_t *add_new_implicit_operand(x86_insn_t *insn, x86_op_t *opd) {

	x86_op_t *result;
	
	result = find_implicit_operand(insn, opd);
	
	if (!result) {
		result = x86_implicit_operand_new(insn);
		memcpy(result, opd, sizeof(x86_op_t));
	}

	return result;
}

x86_op_t *find_implicit_operand(x86_insn_t *insn, x86_op_t *opd) {

	x86_oplist_t *list;

	for (list = insn->operands; list; list = list->next) {
		if (memcmp(&list->op, opd, sizeof(x86_op_t)) == 0) {
			return &list->op;
		}
	}
	return NULL;
}

void convert_offset_to_exp(x86_op_t *opd) {
	unsigned temp; 
	
	if (opd->type == op_offset) {
		opd->type = op_expression;
		temp = opd->data.offset;
		memset(&opd->data.expression, 0, sizeof(x86_ea_t));
		opd->data.expression.disp = temp;
	}
}
