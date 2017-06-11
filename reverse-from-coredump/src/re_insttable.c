#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "global.h"
#include "disassemble.h"
#include "insthandler.h"
#include "reverse_exe.h"

#define insn_systems 0xE000


// function points table for instruction resolver
// Be careful! If you uncomment one instruction type in the middle,
// please modify all the following entries
op_index_pair_t opcode_index_tab[]={
	/* insn_controlflow */
	{insn_jmp,    	0x00},
	{insn_jcc,    	0x01},
	{insn_call,   	0x02},
	{insn_callcc, 	0x03},
	{insn_return, 	0x04},
        /* insn_arithmetic */
	{insn_add,    	0x05},
	{insn_sub,    	0x06},
	{insn_mul,    	0x07},
	{insn_div,    	0x08},
	{insn_inc,    	0x09},
	{insn_dec, 	0x0a},
	{insn_shl, 	0x0b},
	{insn_shr, 	0x0c},
	{insn_rol, 	0x0d},
	{insn_ror, 	0x0e},
        /* insn_logic */
	{insn_and,	0x0f},
	{insn_or,	0x10},
	{insn_xor,	0x11},
	{insn_not,	0x12},
	{insn_neg,	0x13},
        /* insn_stack */
	{insn_push,	0x14},
	{insn_pop,	0x15},
	{insn_pushregs,	0x16},
	{insn_popregs, 	0x17},
	{insn_pushflags,0x18},
	{insn_popflags,	0x19},
	{insn_enter,	0x1a},
	{insn_leave,	0x1b},
        /* insn_comparison */
	{insn_test,	0x1c},
	{insn_cmp,	0x1d},
        /* insn_move */
	{insn_mov,	0x1e},
	{insn_movcc,	0x1f},
	{insn_xchg,	0x20},
	{insn_xchgcc,	0x21},
        /* insn_string */
	{insn_strcmp, 	0x22},
	{insn_strload,	0x23},
	{insn_strmov,	0x24},
	{insn_strstore,	0x25},
	{insn_translate,0x26},
        /* insn_bit_manip */
	{insn_bittest,	0x27},
	{insn_bitset,	0x28},
	{insn_bitclear,	0x29},
	{insn_nop, 0x2a},
	{insn_szconv, 0x2b},
	{insn_unknown, 0x2c},
	{insn_clear_dir, 0x2d},
	{insn_systems, 0x2e},
	{insn_int, 0x2f},
	{insn_in, 0x30},
	{insn_out, 0x31},
	{insn_cpuid, 0x32}
	/* insn_flag_manip 
        insn_clear_carry
        insn_clear_zero
        insn_clear_oflow
        insn_clear_sign
        insn_clear_parity
        insn_set_carry
        insn_set_zero
        insn_set_oflow
        insn_set_dir
        insn_set_sign
        insn_set_parity
        insn_tog_carry
        insn_tog_zero
        insn_tog_oflow
        insn_tog_dir
        insn_tog_sign
        insn_tog_parity */
        /* insn_fpu 
        insn_fmov
        insn_fmovcc
        insn_fneg
        insn_fabs
        insn_fadd
        insn_fsub
        insn_fmul
        insn_fdiv
        insn_fsqrt
        insn_fcmp
        insn_fcos
        insn_fldpi
        insn_fldz
        insn_ftan
        insn_fsine
        insn_fsys*/
        /* insn_interrupt */
        //insn_intcc    /* not present in x86 ISA */
        //insn_iret
        //insn_bound
        //insn_debug
        //insn_trace
        //insn_invalid_op
        //insn_oflow
        /* insn_system */
        //insn_halt
        /* insn_other */
        //insn_bcdconv
};

const int ninst = sizeof(opcode_index_tab) / sizeof (op_index_pair_t);

resolver_func inst_resolver[] = {
	/* insn_controlflow */
	&jmp_resolver, //0
	&jcc_resolver, //1
	&call_resolver, //2
	&callcc_resolver, //3
	&return_resolver, //4
        /* insn_arithmetic */
	&add_resolver, //5
	&sub_resolver, //6
	&mul_resolver,  //7
	&div_resolver, //8 
	&inc_resolver, //9
	&dec_resolver, //10
	&shl_resolver, //11
	&shr_resolver, //12
	&rol_resolver, //13
	&ror_resolver, //14
        /* insn_logic */ 
	&and_resolver, //15
	&or_resolver, //16
	&xor_resolver, //17
	&not_resolver, //18
	&neg_resolver, //19
        /* insn_stack */
	&push_resolver, //20
	&pop_resolver, //21
	&pushregs_resolver, //22
	&popregs_resolver, //23
	&pushflags_resolver, //24
	&popflags_resolver, //25
	&enter_resolver, //26
	&leave_resolver, //27
        /* insn_comparison */
	&test_resolver, //28
	&cmp_resolver,  //29
        /* insn_move */
	&mov_resolver, //30
	&movcc_resolver, //31
	&xchg_resolver, //32
	&xchgcc_resolver, //33
        /* insn_string */ 
	&strcmp_resolver, //34 
	&strload_resolver, //35
	&strmov_resolver, //36
	&strstore_resolver, //37
	&translate_resolver, //38 
        /* insn_bit_manip */
	&bittest_resolver, //39
	&bitset_resolver, //40
	&bitclear_resolver, //41
	/* insn_system */
	//&sysenter_resolver,
	//&halt_resolver,
	//&in_resolver,
	//&out_resolver,
	//&cpuid_resolver,
        /* insn_other */
	&nop_resolver, //42
	&szconv_resolver, //43
	&unknown_resolver, //44
	&clear_dir_resolver, //45
	&sys_resolver, //46
	&int_resolver, //47
	&in_resolver, //48
	&out_resolver, //49
	&cpuid_resolver //50
	//&pxor_resolver,
	//&movdqu_resolver,
	//&pmovmskb_hanlder,
	//&pcmpeqb_resolver,
	//&pminub_resolver,
	//&movaps_resolver
};

handler_func inst_handler[] = {
	/* insn_controlflow */
	&jmp_handler,
	&jcc_handler,
	&call_handler,
	&callcc_handler,
	&return_handler,
        /* insn_arithmetic */
	&add_handler,
	&sub_handler,
	&mul_handler,
	&div_handler,
	&inc_handler,
	&dec_handler,
	&shl_handler,
	&shr_handler,
	&rol_handler,
	&ror_handler,
        /* insn_logic */
	&and_handler,
	&or_handler,
	&xor_handler,
	&not_handler,
	&neg_handler,
        /* insn_stack */
	&push_handler,
	&pop_handler,
	&pushregs_handler,
	&popregs_handler,
	&pushflags_handler,
	&popflags_handler,
	&enter_handler,
	&leave_handler,
        /* insn_comparison */
	&test_handler,
	&cmp_handler,
        /* insn_move */
	&mov_handler,
	&movcc_handler,
	&xchg_handler,
	&xchgcc_handler,
        /* insn_string */
	&strcmp_handler,
	&strload_handler,
	&strmov_handler,
	&strstore_handler,
	&translate_handler,
        /* insn_bit_manip */
	&bittest_handler,
	&bitset_handler,
	&bitclear_handler,
        /* insn_system */
	//&sysenter_handler,
	//&halt_handler,
	//&in_handler,
	//&out_handler,
	//&cpuid_handler
        /* insn_other */
	&nop_handler,
	&szconv_handler,
	&unknown_handler,
	&clear_dir_handler,
	&sys_handler,
	&int_handler,
	&in_handler,
	&out_handler,
	&cpuid_handler
	//&pxor_handler,
	//&movdqu_handler,
	//&pmovmskb_hanlder,
	//&pcmpeqb_handler,
	//&pminub_handler,
	//&movaps_handler
};

post_resolve_heuristic_func post_resolve_heuristics[] = {
        /* insn_controlflow */
        &jmp_post_res, //0
        &jcc_post_res, //1
        &call_post_res, //2
        &callcc_post_res, //3
        &return_post_res, //4
        /* insn_arithmetic */
        &add_post_res, //5
        &sub_post_res, //6
        &mul_post_res,  //7
        &div_post_res, //8 
        &inc_post_res, //9
        &dec_post_res, //10
        &shl_post_res, //11
        &shr_post_res, //12
        &rol_post_res, //13
        &ror_post_res, //14
        /* insn_logic */
        &and_post_res, //15
        &or_post_res, //16
        &xor_post_res, //17
        &not_post_res, //18
        &neg_post_res, //19
        /* insn_stack */
        &push_post_res, //20
        &pop_post_res, //21
        &pushregs_post_res, //22
        &popregs_post_res, //23
        &pushflags_post_res, //24
        &popflags_post_res, //25
        &enter_post_res, //26
        &leave_post_res, //27
        /* insn_comparison */
        &test_post_res, //28
        &cmp_post_res,  //29
	/* insn_move */
        &mov_post_res, //30
        &movcc_post_res, //31
        &xchg_post_res, //32
        &xchgcc_post_res, //33
        /* insn_string */
        &strcmp_post_res, //34 
        &strload_post_res, //35
        &strmov_post_res, //36
        &strstore_post_res, //37
        &translate_post_res, //38 
        /* insn_bit_manip */
        &bittest_post_res, //39
        &bitset_post_res, //40
        &bitclear_post_res, //41
        &nop_post_res, //42
	&szconv_post_res, //43
        &unknown_post_res, //44
        &clear_dir_post_res, //45
        &sys_post_res, //46
        &int_post_res, //47
        &in_post_res, //48
        &out_post_res, //49
        &cpuid_post_res //50
        /* insn_system */
        //&sysenter_resolver,
        //&halt_resolver,
        //&in_resolver,
        //&out_resolver,
        //&cpuid_resolver,
        /* insn_other */
        //&pxor_resolver,
        //&movdqu_resolver,
        //&pmovmskb_hanlder,
        //&pcmpeqb_resolver,
        //&pminub_resolver,
        //&movaps_resolver
};


