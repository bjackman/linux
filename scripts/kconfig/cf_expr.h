/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Patrick Franz <deltaone@debian.org>
 */

#ifndef CF_EXPR_H
#define CF_EXPR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

#include "cf_defs.h"

/* call pexpr_put for a list of pexpr's */
#define PEXPR_PUT(...) _pexpr_put_list((struct pexpr *[]){ __VA_ARGS__, NULL })

/* create a fexpr */
struct fexpr *fexpr_create(int satval, enum fexpr_type type, char *name);

/* create the fexpr for a symbol */
void sym_create_fexpr(struct symbol *sym, struct cfdata *data);

struct pexpr *expr_calculate_pexpr_both(struct expr *e, struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y(struct expr *e, struct cfdata *data);
struct pexpr *expr_calculate_pexpr_m(struct expr *e, struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_and(struct expr *a, struct expr *b,
					 struct cfdata *data);
struct pexpr *expr_calculate_pexpr_m_and(struct expr *a, struct expr *b,
					 struct cfdata *data);
struct pexpr *expr_calculate_pexpr_both_and(struct expr *a, struct expr *b,
					    struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_or(struct expr *a, struct expr *b,
					struct cfdata *data);
struct pexpr *expr_calculate_pexpr_m_or(struct expr *a, struct expr *b,
					struct cfdata *data);
struct pexpr *expr_calculate_pexpr_both_or(struct expr *a, struct expr *b,
					   struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_not(struct expr *e, struct cfdata *data);
struct pexpr *expr_calculate_pexpr_m_not(struct expr *e, struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_equals(struct expr *e,
					    struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_unequals(struct expr *e,
					      struct cfdata *data);
struct pexpr *expr_calculate_pexpr_y_comp(struct expr *e, struct cfdata *data);

/* macro to create a pexpr of type AND */
struct pexpr *pexpr_and_share(struct pexpr *a, struct pexpr *b,
			      struct cfdata *data);
struct pexpr *pexpr_and(struct pexpr *a, struct pexpr *b, struct cfdata *data,
			enum pexpr_move move);

/* macro to create a pexpr of type OR */
struct pexpr *pexpr_or_share(struct pexpr *a, struct pexpr *b,
			     struct cfdata *data);
struct pexpr *pexpr_or(struct pexpr *a, struct pexpr *b, struct cfdata *data,
		       enum pexpr_move move);

/* macro to create a pexpr of type NOT */
struct pexpr *pexpr_not_share(struct pexpr *a, struct cfdata *data);
struct pexpr *pexpr_not(struct pexpr *a, struct cfdata *data);

/* check whether a pexpr is in CNF */
bool pexpr_is_cnf(struct pexpr *e);

/* check whether a pexpr is in NNF */
bool pexpr_is_nnf(struct pexpr *e);

/* return fexpr_both for a symbol */
struct pexpr *sym_get_fexpr_both(struct symbol *sym, struct cfdata *data);

/* return fexpr_sel_both for a symbol */
struct pexpr *sym_get_fexpr_sel_both(struct symbol *sym, struct cfdata *data);

/* create the fexpr of a non-boolean symbol for a specific value */
struct fexpr *sym_create_nonbool_fexpr(struct symbol *sym, char *value,
				       struct cfdata *data);

/*
 * return the fexpr of a non-boolean symbol for a specific value, NULL if
 * non-existent
 */
struct fexpr *sym_get_nonbool_fexpr(struct symbol *sym, char *value);

/*
 * return the fexpr of a non-boolean symbol for a specific value, if it exists
 * otherwise create it
 */
struct fexpr *sym_get_or_create_nonbool_fexpr(struct symbol *sym, char *value,
					      struct cfdata *data);

/* macro to construct a pexpr for "A implies B" */
struct pexpr *pexpr_implies_share(struct pexpr *a, struct pexpr *b,
				  struct cfdata *data);
struct pexpr *pexpr_implies(struct pexpr *a, struct pexpr *b,
			    struct cfdata *data, enum pexpr_move move);

/* check, if the fexpr is a symbol, a True/False-constant, a literal symbolising
 * a non-boolean or a choice symbol
 */
bool fexpr_is_symbol(struct fexpr *e);

/* check whether a pexpr is a symbol or a negated symbol */
bool pexpr_is_symbol(struct pexpr *e);

/* check whether the fexpr is a constant (true/false) */
bool fexpr_is_constant(struct fexpr *e, struct cfdata *data);

/* add a fexpr to the satmap */
void fexpr_add_to_satmap(struct fexpr *e, struct cfdata *data);

/* print an fexpr */
void fexpr_print(char *tag, struct fexpr *e);

/* write an fexpr into a string (format needed for testing) */
void fexpr_as_char(struct fexpr *e, struct gstr *s);

/* write pn pexpr into a string */
void pexpr_as_char_short(struct pexpr *e, struct gstr *s, int parent);

/* write an fexpr into a string (format needed for testing) */
void pexpr_as_char(struct pexpr *e, struct gstr *s, int parent,
		   struct cfdata *data);

/* check whether a pexpr contains a specific fexpr */
bool pexpr_contains_fexpr(struct pexpr *e, struct fexpr *fe);

/* print a fexpr_list */
void fexpr_list_print(char *title, struct fexpr_list *list);

/* print a fexl_list */
void fexl_list_print(char *title, struct fexl_list *list);

/* print a pexpr_list */
void pexpr_list_print(char *title, struct pexpr_list *list);

/* free an pexpr_list (and pexpr_put the elements) */
void pexpr_list_free_put(struct pexpr_list *list);

/* free a defm_list (and pexpr_put the conditions of the maps) */
void defm_list_destruct(struct defm_list *list);

/* check whether 2 pexpr are equal */
bool pexpr_test_eq(struct pexpr *e1, struct pexpr *e2, struct cfdata *data);

/* copy a pexpr */
struct pexpr *pexpr_deep_copy(const struct pexpr *org);

void pexpr_construct_sym(struct pexpr *e, struct fexpr *left,
			 unsigned int ref_count);
void pexpr_construct_not(struct pexpr *e, struct pexpr *left,
			 unsigned int ref_count);
void pexpr_construct_and(struct pexpr *e, struct pexpr *left,
			 struct pexpr *right, unsigned int ref_count);
void pexpr_construct_or(struct pexpr *e, struct pexpr *left,
			struct pexpr *right, unsigned int ref_count);

/* free a pexpr */
void pexpr_free_depr(struct pexpr *e);

/* give up a reference to e. Also see struct pexpr. */
void pexpr_put(struct pexpr *e);
/* Used by PEXPR_PUT(). Not to be used directly. */
void _pexpr_put_list(struct pexpr **es);

/* acquire a reference to e. Also see struct pexpr. */
struct pexpr *pexpr_get(struct pexpr *e);

/* print a pexpr  */
void pexpr_print(char *tag, struct pexpr *e, int prevtoken);

/* convert a fexpr to a pexpr */
struct pexpr *pexpr_alloc_symbol(struct fexpr *fe);

#ifdef __cplusplus
}
#endif

#endif
