/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Patrick Franz <deltaone@debian.org>
 */

#ifndef CF_CONSTRAINTS_H
#define CF_CONSTRAINTS_H

#include "cf_defs.h"
#include "expr.h"

/* build the constraints for each symbol */
void build_constraints(struct cfdata *data);

/* count the number of all constraints */
unsigned int count_constraints(void);

/* add a constraint for a symbol */
void sym_add_constraint(struct symbol *sym, struct pexpr *constraint, struct cfdata *data);

/* add a constraint for a symbol, but check for duplicate constraints */
void sym_add_constraint_unique(struct symbol *sym, struct pexpr *constraint, struct cfdata *data);

#endif
