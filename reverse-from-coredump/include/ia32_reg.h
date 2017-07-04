#ifndef IA32_REG_H
#define IA32_REG_H

/* NOTE these are used in opcode tables for hard-coded registers */
#define REG_DWORD_OFFSET 	 1	/* 0 + 1 */
#define REG_ECX_INDEX		 2	/* 0 + 1 + 1 */
#define REG_ESP_INDEX		 5	/* 0 + 4 + 1 */
#define REG_EBP_INDEX		 6	/* 0 + 5 + 1 */
#define REG_ESI_INDEX		 7	/* 0 + 6 + 1 */
#define REG_EDI_INDEX		 8	/* 0 + 7 + 1 */
#define REG_WORD_OFFSET 	 9	/* 1 * 8 + 1 */
#define REG_BYTE_OFFSET 	17	/* 2 * 8 + 1 */
#define REG_MMX_OFFSET 		25	/* 3 * 8 + 1 */
#define REG_SIMD_OFFSET 	33	/* 4 * 8 + 1 */
#define REG_DEBUG_OFFSET 	41	/* 5 * 8 + 1 */
#define REG_CTRL_OFFSET 	49	/* 6 * 8 + 1 */
#define REG_TEST_OFFSET 	57	/* 7 * 8 + 1 */
#define REG_SEG_OFFSET 		65	/* 8 * 8 + 1 */
#define REG_LDTR_INDEX		71	/* 8 * 8 + 1 + 1 */
#define REG_GDTR_INDEX		72	/* 8 * 8 + 2 + 1 */
#define REG_FPU_OFFSET 		73	/* 9 * 8 + 1 */
#define REG_FLAGS_INDEX 	81	/* 10 * 8 + 1 */
#define REG_FPCTRL_INDEX 	82	/* 10 * 8 + 1 + 1 */
#define REG_FPSTATUS_INDEX 	83	/* 10 * 8 + 2 + 1 */
#define REG_FPTAG_INDEX 	84	/* 10 * 8 + 3 + 1 */
#define REG_EIP_INDEX 		85	/* 10 * 8 + 4 + 1 */
#define REG_IP_INDEX 		86	/* 10 * 8 + 5 + 1 */
#define REG_IDTR_INDEX		87	/* 10 * 8 + 6 + 1 */
#define REG_MXCSG_INDEX		88	/* 10 * 8 + 7 + 1 */
#define REG_TR_INDEX		89	/* 10 * 8 + 8 + 1 */
#define REG_CSMSR_INDEX		90	/* 10 * 8 + 9 + 1 */
#define REG_ESPMSR_INDEX	91	/* 10 * 8 + 10 + 1 */
#define REG_EIPMSR_INDEX	92	/* 10 * 8 + 11 + 1 */

#define get_eflags_id() \
    (REG_FLAGS_INDEX)

#define get_eip_id() \
    (REG_EIP_INDEX)

#define get_eax_id() \
    (REG_DWORD_OFFSET)

#define get_ecx_id() \
    (REG_DWORD_OFFSET + 1)

#define get_edx_id() \
    (REG_DWORD_OFFSET + 2)

#define get_ebx_id() \
    (REG_DWORD_OFFSET + 3)

#define get_esp_id() \
    (REG_DWORD_OFFSET + 4)

#define get_ebp_id() \
    (REG_DWORD_OFFSET + 5)

#define get_esi_id() \
    (REG_DWORD_OFFSET + 6)

#define get_edi_id() \
    (REG_DWORD_OFFSET + 7)

#define get_ax_id() \
    (REG_WORD_OFFSET)

#define get_cx_id() \
    (REG_WORD_OFFSET + 1)

#define get_dx_id() \
    (REG_WORD_OFFSET + 2)

#define get_bx_id() \
    (REG_WORD_OFFSET + 3)

#define get_sp_id() \
    (REG_WORD_OFFSET + 4)

#define get_bp_id() \
    (REG_WORD_OFFSET + 5)

#define get_si_id() \
    (REG_WORD_OFFSET + 6)

#define get_di_id() \
    (REG_WORD_OFFSET + 7)

#define get_al_id() \
    (REG_BYTE_OFFSET)

#define get_cl_id() \
    (REG_BYTE_OFFSET + 1)

#define get_dl_id() \
    (REG_BYTE_OFFSET + 2)

#define get_bl_id() \
    (REG_BYTE_OFFSET + 3)

#define get_ah_id() \
    (REG_BYTE_OFFSET + 4)

#define get_ch_id() \
    (REG_BYTE_OFFSET + 5)

#define get_dh_id() \
    (REG_BYTE_OFFSET + 6)

#define get_bh_id() \
    (REG_BYTE_OFFSET + 7)

#define H8_REG(id) \
    (((id) >= REG_BYTE_OFFSET + 4) && ((id) <= REG_BYTE_OFFSET + 7))

#endif
