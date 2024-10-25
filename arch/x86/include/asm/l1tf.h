/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_L1TF_FLUSH_H
#define _ASM_L1TF_FLUSH_H

#ifdef CONFIG_X86_L1TF_FLUSH_LIB
int l1tf_flush_setup(void);
void l1tf_flush(void);
#endif /* CONFIG_X86_L1TF_FLUSH_LIB */

#endif

