/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Patrick Franz <deltaone@debian.org>
 */

#ifndef CONFIGFIX_H
#define CONFIGFIX_H

/* make functions accessible from xconfig */
#ifdef __cplusplus
extern "C" {
#endif

/* include own definitions */
#include "cf_defs.h"

/* external functions */
struct sfix_list **run_satconf(struct symbol_dvalue **symbols, size_t n,
			       size_t *num_solutions);
struct sfl_list *run_satconf_list(struct sdv_list *symbols);
int apply_fix(struct sfix_list *fix);
int run_satconf_cli(const char *Kconfig_file);
void interrupt_rangefix(void);
struct sfix_list *select_solution(struct sfl_list *solutions, int index);
struct symbol_fix *select_symbol(struct sfix_list *solution, int index);

/* make functions accessible from xconfig */
#ifdef __cplusplus
}
#endif
#endif
