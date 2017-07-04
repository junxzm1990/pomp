bin_PROGRAMS = reverse

#AM_CFLAGS= -DDEBUG -DLOG_INSTRUCTIONS -I ../include
AM_CFLAGS= -O0 -DBIN_ALIAS -DDATA_LOGGED -DDEBUG -DFIX_OPTM -I ../include

reverse_CPPFLAGS = -msse4.1

handlers_FILES = handler_arithmetic.c handler_bit_manip.c handler_comparison.c handler_controlflow.c handler_logic.c handler_move.c handler_other.c handler_sse.c handler_stack.c handler_string.c handler_system.c handler_flag_manip.c handler_interrupt.c

#handler_interrupt.c

reverse_SOURCES = solver.c access_memory.c alias_manager.c common.c disassemble.c heuristics.c global.c inst_handle_resolve.c process_binary.c process_core.c process_inst_data.c process_thread.c re_dsmanager.c re_insttable.c re_mem_alias.c re_opdvalue.c reverse_log.c analyze_result.c reverse_execution.c reverse_instructions.c bin_alias.c $(handlers_FILES)
