/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM asi

#if !defined(_TRACE_ASI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_ASI_H

#include <linux/build_bug.h>
#include <linux/tracepoint.h>

#ifdef CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION

TRACE_EVENT(asi_exit_pf,

	TP_PROTO(unsigned long address, struct pt_regs *regs,
		 unsigned long error_code, bool user_mode),

	TP_ARGS(address, regs, error_code, user_mode),

	TP_STRUCT__entry(
		__field(unsigned long,	address)
		__field(unsigned long,	ip)
		__field(unsigned long,	error_code)
		__field(bool,		user_mode)
	),

	TP_fast_assign(
		__entry->address = address;
		__entry->ip = regs->ip;
		__entry->error_code = error_code;
		__entry->user_mode = user_mode;
	),

	TP_printk("address=%pS ip=%pS error_code=0x%lx, user_mode=%d",
		  (void *)__entry->address, (void *)__entry->ip,
		  __entry->error_code, __entry->user_mode)
);
#else

#define trace_asi_exit_pf(...) ((void)(0))

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE asi
#endif /*  _TRACE_ASI_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

