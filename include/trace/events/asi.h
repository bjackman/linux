/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM asi

#if !defined(_TRACE_EVENTS_ASI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENTS_ASI_H

#include <linux/build_bug.h>
#include <linux/compiler_attributes.h>
#include <linux/tracepoint.h>

#ifdef CONFIG_ADDRESS_SPACE_ISOLATION

TRACE_EVENT(
	asi_exit_pf,

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
		__entry->user_mode = error_code;
	),

	TP_printk("address=%pS ip=%pS error_code=0x%lx, user_mode=%d",
		  (void *)__entry->address, (void *)__entry->ip,
		  __entry->error_code, __entry->user_mode)
);
#else

/*
 * All ASI operations are NOPs, but code is still sprinkled throughout the
 * kernel. To avoid creating a confusing entry in available_events etc, stub out
 * the tracepoint too.
 */
#define trace_asi_exit_pf(a, r, e, u) ({				\
	BUILD_BUG_ON_INVALID(a);					\
	BUILD_BUG_ON_INVALID(r);					\
	BUILD_BUG_ON_INVALID(e);					\
	BUILD_BUG_ON_INVALID(u);					\
})

#endif /* CONFIG_MITIGATION_ADDRESS_SPACE_ISOLATION */

#endif /*  _TRACE_EVENTS_ASI_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

