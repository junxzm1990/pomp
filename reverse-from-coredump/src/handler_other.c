#include "insthandler.h"

#define PXOR 0x00
#define MOVDQU 0x01
#define PMOVMSKB 0x02
#define PCMPEQB 0x03
#define PMINUB 0x04
#define MOVAPS 0x05
#define MOVDQA 0x06
#define MOVQ 0x07
#define MOVD 0x08
#define PSHUFD 0x09
#define PUNPCKLBW 0x0A
#define PTEST 0x0B

#define BADINST -1

typedef struct { char *key; int val; } string_kv;
static string_kv insttable[] = {
    {"pxor", PXOR},
    {"movdqu", MOVDQU},
    {"pmovmskb", PMOVMSKB},
    {"pcmpeqb", PCMPEQB},
    {"pminub", PMINUB},
    {"movaps", MOVAPS},
    {"movdqa", MOVDQA},
    {"movq", MOVQ},
    {"movd", MOVD},
    {"pshufd", PSHUFD},
    {"punpcklbw", PUNPCKLBW},
    {"ptest", PTEST}
};

#define NKEYS (sizeof(insttable)/sizeof(string_kv))

int string2int(char *key)
{
    int i;
    for (i=0; i < NKEYS; i++) {
	string_kv sym = insttable[i];	
        if (strcmp(sym.key, key) == 0)
            return sym.val;
    }
    return BADINST;
}

void unknown_handler(re_list_t * instnode){
	//Handling all unknown instructions here
	//Just for now. Need to improve the instruction classification in the future. 
	//really need to do so many if else?
	
	x86_insn_t* inst;
	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;


	switch(string2int(inst->mnemonic)){

		case PXOR:
			pxor_handler(instnode);
			break;

		case MOVDQU:
			movdqu_handler(instnode);
			break;


		case PMOVMSKB:
			pmovmskb_hanlder(instnode);
			break;


		case PCMPEQB:
			pcmpeqb_handler(instnode);
			break;

		case PMINUB: 
			pminub_handler(instnode);
			break;

		case MOVAPS: 
			movaps_handler(instnode);
			break;

		case MOVDQA:
			movdqa_handler(instnode);
			break;
				
		case MOVQ: 
			movq_handler(instnode);
			break;

		case MOVD:
			movq_handler(instnode);
			break;

		case PSHUFD:
			pshufd_handler(instnode);
			break;

		case PUNPCKLBW:
			punpcklbw_handler(instnode);
			break;

		case PTEST:
			ptest_handler(instnode);
			break;
/*
		case BADINST:
			LOG(stdout, "Warning: bad instruction\n");
			break;
*/
		default:
			assert(0);
			LOG(stdout, "Error: this will never happen\n");
			break;
		}
}

void unknown_resolver(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist){


	x86_insn_t* inst;
	inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;

	switch(string2int(inst->mnemonic)){

		case PXOR:
			pxor_resolver(instnode, re_deflist, re_uselist);
			break;
		case MOVDQU: 
			movdqu_resolver(instnode, re_deflist, re_uselist);	
			break;	

		case PMOVMSKB:
			pmovmskb_resolver(instnode, re_deflist, re_uselist);			
			break;
		case PCMPEQB:
			pcmpeqb_resolver(instnode, re_deflist, re_uselist);
			break; 
		
		case PMINUB:
			pminub_resolver(instnode, re_deflist, re_uselist);
			break;

		case MOVAPS:
			movaps_resolver(instnode, re_deflist, re_uselist);
			break;

		case MOVDQA:
			movdqa_resolver(instnode, re_deflist, re_uselist);
			break;

		case MOVQ: 
			movq_resolver(instnode, re_deflist, re_uselist);
			break;

		case MOVD:
			movq_resolver(instnode, re_deflist, re_uselist);
			break;

		case PSHUFD:
			pshufd_resolver(instnode, re_deflist, re_uselist);
			break;

		case PUNPCKLBW:
			punpcklbw_resolver(instnode, re_deflist, re_uselist);
			break;

		case PTEST:
			ptest_resolver(instnode, re_deflist, re_uselist);
			break;
		default:
			assert(0);
			break;	
	}
}

void nop_handler(re_list_t * instnode){
}

void nop_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
}

void szconv_handler(re_list_t * instnode){

	x86_insn_t* inst;
	x86_op_t *src, *dst;
	re_list_t re_deflist, re_uselist, re_instlist;  	
	re_list_t *def, *usesrc;

        inst = re_ds.instlist + CAST2_INST(instnode->node)->inst_index;
	src = x86_implicit_operand_1st(inst);
	dst = x86_implicit_operand_2nd(inst);

	//	for debugginf use	
	print_all_operands(inst);

	INIT_LIST_HEAD(&re_deflist.deflist);
	INIT_LIST_HEAD(&re_uselist.uselist);
	INIT_LIST_HEAD(&re_instlist.instlist);	
	
	def = add_new_define(dst);
	usesrc = add_new_use(src, Opd);
	
	add_to_instlist(instnode, &re_instlist);

	re_resolve(&re_deflist, &re_uselist, &re_instlist);
	print_info_of_current_inst(instnode);
}

void szconv_resolver(re_list_t* inst, re_list_t *re_deflist, re_list_t *re_uselist){
	re_list_t *entry;
	re_list_t *dst[NOPD], *src[NOPD];
	int nuse, ndef;
	valset_u  vt = {0};
	
	traverse_inst_operand(inst, src, dst, re_uselist, re_deflist, &nuse, &ndef);
	
	assert(nuse == 1 && ndef ==1);

	if (sign_of_valset(&(CAST2_USE(src[0]->node)->val), CAST2_USE(src[0]->node)->operand->datatype)) {
		one_valset(&vt);
	} else {
		zero_valset(&vt);
	}

	if (CAST2_USE(src[0]->node)->val_known 
			&& (CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){
		assert_val(dst[0], vt, false);
	}

	if (CAST2_USE(src[0]->node)->val_known 
			&& !(CAST2_DEF(dst[0]->node)->val_stat & AfterKnown)){

		assign_def_after_value(dst[0], vt);
		add_to_deflist(dst[0], re_deflist);
	}
}
