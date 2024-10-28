// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 Patrick Franz <deltaone@debian.org>
 */

#define _GNU_SOURCE
#include <assert.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <xalloc.h>

#include "lkc.h"
#include "list.h"
#include "cf_expr.h"
#include "cf_defs.h"
#include "cf_utils.h"

static void create_fexpr_bool(struct symbol *sym, struct cfdata *data);
static void create_fexpr_nonbool(struct symbol *sym, struct cfdata *data);
static void create_fexpr_unknown(struct symbol *sym, struct cfdata *data);
static void create_fexpr_choice(struct symbol *sym, struct cfdata *data);

static void pexpr_print_util(struct pexpr *e, int prevtoken);
static void pexpr_shallow_copy(struct pexpr *dest, struct pexpr *org,
			       unsigned int ref_count);

static struct pexpr *pexpr_move_wrapper(
	struct pexpr *a, struct pexpr *b, struct cfdata *data,
	enum pexpr_move move,
	struct pexpr *(*func)(struct pexpr *, struct pexpr *, struct cfdata *));

static int trans_count;


/*
 *  create a fexpr
 */
struct fexpr *fexpr_create(int satval, enum fexpr_type type, char *name)
{
	struct fexpr *e = xcalloc(1, sizeof(*e));

	e->satval = satval;
	e->type = type;
	e->name = str_new();
	e->assumption = false;
	str_append(&e->name, name);

	return e;
}

/*
 * create the fexpr for a symbol
 */
void sym_create_fexpr(struct symbol *sym, struct cfdata *data)
{
	if (sym_is_choice(sym))
		create_fexpr_choice(sym, data);
	else if (sym_is_boolean(sym))
		create_fexpr_bool(sym, data);
	else if (sym_is_nonboolean(sym))
		create_fexpr_nonbool(sym, data);
	else
		create_fexpr_unknown(sym, data);
}

/*
 * create the fexpr for symbols with reverse dependencies
 */
static void create_fexpr_selected(struct symbol *sym, struct cfdata *data)
{
	struct fexpr *fexpr_sel_y;
	struct fexpr *fexpr_sel_m;

	/* fexpr_sel_y */
	fexpr_sel_y =
		fexpr_create(data->sat_variable_nr++, FE_SELECT, sym->name);
	str_append(&fexpr_sel_y->name, "_sel_y");
	fexpr_sel_y->sym = sym;
	fexpr_add_to_satmap(fexpr_sel_y, data);

	sym->fexpr_sel_y = fexpr_sel_y;

	/* fexpr_sel_m */
	if (sym->type == S_BOOLEAN)
		return;

	fexpr_sel_m =
		fexpr_create(data->sat_variable_nr++, FE_SELECT, sym->name);
	str_append(&fexpr_sel_m->name, "_sel_m");
	fexpr_sel_m->sym = sym;
	fexpr_add_to_satmap(fexpr_sel_m, data);

	sym->fexpr_sel_m = fexpr_sel_m;
}

/*
 * create the fexpr for a boolean/tristate symbol
 */
static void create_fexpr_bool(struct symbol *sym, struct cfdata *data)
{
	struct fexpr *fexpr_y;
	struct fexpr *fexpr_m;

	fexpr_y = fexpr_create(data->sat_variable_nr++, FE_SYMBOL, sym->name);
	fexpr_y->sym = sym;
	fexpr_y->tri = yes;
	fexpr_add_to_satmap(fexpr_y, data);

	sym->fexpr_y = fexpr_y;


	if (sym->type == S_TRISTATE) {
		fexpr_m = fexpr_create(data->sat_variable_nr++, FE_SYMBOL,
				       sym->name);
		str_append(&fexpr_m->name, "_MODULE");
		fexpr_m->sym = sym;
		fexpr_m->tri = mod;
		fexpr_add_to_satmap(fexpr_m, data);
	} else {
		fexpr_m = data->constants->const_false;
	}

	sym->fexpr_m = fexpr_m;

	if (sym->rev_dep.expr)
		create_fexpr_selected(sym, data);
}

/*
 * create the fexpr for a non-boolean symbol
 */
static void create_fexpr_nonbool(struct symbol *sym, struct cfdata *data)
{
	/* default values */
	char int_values[][2] = {"n", "0", "1"};
	char hex_values[][4] = {"n", "0x0", "0x1"};
	char string_values[][9] = {"n", "", "nonempty"};

	sym->fexpr_y = data->constants->const_false;
	sym->fexpr_m = data->constants->const_false;
	sym->nb_vals = xmalloc(sizeof(*sym->nb_vals));
	INIT_LIST_HEAD(&sym->nb_vals->list);

	for (int i = 0; i < 3; i++) {
		struct fexpr *e = fexpr_create(data->sat_variable_nr++,
					       FE_NONBOOL, sym->name);

		e->sym = sym;
		str_append(&e->name, "=");
		e->nb_val = str_new();

		switch (sym->type) {
		case S_INT:
			str_append(&e->name, int_values[i]);
			str_append(&e->nb_val, int_values[i]);
			break;
		case S_HEX:
			str_append(&e->name, hex_values[i]);
			str_append(&e->nb_val, hex_values[i]);
			break;
		case S_STRING:
			str_append(&e->name, string_values[i]);
			str_append(&e->nb_val, string_values[i]);
			break;
		default:
			break;
		}

		CF_PUSH_BACK(sym->nb_vals, e, fexpr);
		fexpr_add_to_satmap(e, data);
	}
}

/*
 * set fexpr_y and fexpr_m simply to False
 */
static void create_fexpr_unknown(struct symbol *sym, struct cfdata *data)
{
	sym->fexpr_y = data->constants->const_false;
	sym->fexpr_m = data->constants->const_false;
}

/*
 * create the fexpr for a choice symbol
 */
static void create_fexpr_choice(struct symbol *sym, struct cfdata *data)
{
	struct property *prompt;
	char *name, *write, *read;
	struct fexpr *fexpr_y;
	struct fexpr *fexpr_m;

	if (!sym_is_boolean(sym))
		return;

	prompt = sym_get_prompt(sym);
	if (prompt == NULL) {
		perror("Choice symbol should have a prompt.");
		return;
	}

	name = strdup(prompt->text);

	/* remove spaces */
	write = name;
	read = name;
	do {
		if (*read != ' ')
			*write++ = *read;
	} while (*read++);

	fexpr_y = fexpr_create(data->sat_variable_nr++, FE_CHOICE, "Choice_");
	str_append(&fexpr_y->name, name);
	fexpr_y->sym = sym;
	fexpr_y->tri = yes;
	fexpr_add_to_satmap(fexpr_y, data);

	sym->fexpr_y = fexpr_y;

	if (sym->type == S_TRISTATE) {
		fexpr_m = fexpr_create(data->sat_variable_nr++, FE_CHOICE,
				       "Choice_");
		str_append(&fexpr_m->name, name);
		str_append(&fexpr_m->name, "_MODULE");
		fexpr_m->sym = sym;
		fexpr_m->tri = mod;
		fexpr_add_to_satmap(fexpr_m, data);
	} else {
		fexpr_m = data->constants->const_false;
	}
	sym->fexpr_m = fexpr_m;
	free(name);
}

/*
 * evaluate an unequality between a non-Boolean symbol and a constant
 */
static struct pexpr *expr_eval_unequal_nonbool_const(struct symbol *sym,
						     struct symbol *compval,
						     enum expr_type type,
						     struct cfdata *data)
{
	int base;
	struct pexpr *c;
	long val;
	struct fexpr_node *node;
	struct fexpr *fe;
	bool first;

	if (!sym || !compval)
		return pexpr_alloc_symbol(data->constants->const_false);

	base = 0;
	switch (sym->type) {
	case S_INT:
		base = 10;
		break;
	case S_HEX:
		base = 16;
		break;
	default:
		break;
	}

	c = pexpr_alloc_symbol(data->constants->const_false);
	val = strtol(compval->name, NULL, base);
	first = true;
	CF_LIST_FOR_EACH(node, sym->nb_vals, fexpr) {
		long symval;

		if (first) {
			first = false;
			continue;
		}
		fe = node->elem;
		symval = strtol(str_get(&fe->nb_val), NULL, base);

		switch (type) {
		case E_LTH:
			if (symval < val)
				c = pexpr_or(c, pexpr_alloc_symbol(fe), data,
					     PEXPR_ARGX);
			break;
		case E_LEQ:
			if (symval <= val)
				c = pexpr_or(c, pexpr_alloc_symbol(fe), data,
					     PEXPR_ARGX);
			break;
		case E_GTH:
			if (symval > val)
				c = pexpr_or(c, pexpr_alloc_symbol(fe), data,
					     PEXPR_ARGX);
			break;
		case E_GEQ:
			if (symval >= val)
				c = pexpr_or(c, pexpr_alloc_symbol(fe), data,
					     PEXPR_ARGX);
			break;
		default:
			perror("Illegal unequal.");
		}
	}

	return c;
}

/*
 * evaluate an unequality between 2 Boolean symbols
 */
static struct pexpr *expr_eval_unequal_bool(struct symbol *left,
					    struct symbol *right,
					    enum expr_type type,
					    struct cfdata *data)
{
	struct pexpr *c;

	if (!left || !right)
		return pexpr_alloc_symbol(data->constants->const_false);

	if (!sym_is_boolean(left) || !sym_is_boolean(right)) {
		perror("Comparing 2 symbols that should be boolean.");
		return pexpr_alloc_symbol(data->constants->const_false);
	}

	switch (type) {
	case E_LTH:
		c = pexpr_and(pexpr_not(sym_get_fexpr_both(left, data), data),
			      sym_get_fexpr_both(right, data), data,
			      PEXPR_ARGX);
		if (left->type == S_TRISTATE)
			c = pexpr_or(
				c,
				pexpr_and(pexpr_alloc_symbol(left->fexpr_m),
					  pexpr_alloc_symbol(right->fexpr_y),
					  data, PEXPR_ARGX),
				data, PEXPR_ARGX);
		break;
	case E_LEQ:
		c = pexpr_and(pexpr_alloc_symbol(left->fexpr_y),
			      pexpr_alloc_symbol(right->fexpr_y), data,
			      PEXPR_ARGX);
		if (left->type == S_TRISTATE)
			c = pexpr_or(
				c,
				pexpr_and(pexpr_alloc_symbol(left->fexpr_m),
					  sym_get_fexpr_both(right, data), data,
					  PEXPR_ARGX),
				data, PEXPR_ARGX);
		c = pexpr_or(c, pexpr_not(sym_get_fexpr_both(left, data), data),
			     data, PEXPR_ARGX);
		break;
	case E_GTH:
		c = pexpr_and(sym_get_fexpr_both(left, data),
			      pexpr_not(sym_get_fexpr_both(right, data), data),
			      data, PEXPR_ARGX);
		if (right->type == S_TRISTATE)
			c = pexpr_or(
				c,
				pexpr_and(pexpr_alloc_symbol(left->fexpr_y),
					  pexpr_alloc_symbol(right->fexpr_m),
					  data, PEXPR_ARGX),
				data, PEXPR_ARGX);
		break;
	case E_GEQ:
		c = pexpr_and(pexpr_alloc_symbol(left->fexpr_y),
			      pexpr_alloc_symbol(right->fexpr_y), data,
			      PEXPR_ARGX);
		if (right->type == S_TRISTATE)
			c = pexpr_or(
				c,
				pexpr_and(sym_get_fexpr_both(left, data),
					  pexpr_alloc_symbol(right->fexpr_m),
					  data, PEXPR_ARGX),
				data, PEXPR_ARGX);
		c = pexpr_or(c,
			     pexpr_not(sym_get_fexpr_both(right, data), data),
			     data, PEXPR_ARGX);
		break;
	default:
		fprintf(stderr, "Wrong type - %s", __func__);
		c = pexpr_alloc_symbol(data->constants->const_false);
	}

	return c;
}
/*
 * calculate, when expr will evaluate to yes or mod
 */
struct pexpr *expr_calculate_pexpr_both(struct expr *e, struct cfdata *data)
{
	if (!e)
		return pexpr_alloc_symbol(data->constants->const_false);

	if (!expr_can_evaluate_to_mod(e))
		return expr_calculate_pexpr_y(e, data);

	switch (e->type) {
	case E_SYMBOL:
		return pexpr_or(expr_calculate_pexpr_m(e, data),
				expr_calculate_pexpr_y(e, data), data,
				PEXPR_ARGX);
	case E_AND:
		return expr_calculate_pexpr_both_and(e->left.expr,
						     e->right.expr, data);
	case E_OR:
		return expr_calculate_pexpr_both_or(e->left.expr, e->right.expr,
						    data);
	case E_NOT:
		return pexpr_or(expr_calculate_pexpr_m(e, data),
				expr_calculate_pexpr_y(e, data), data,
				PEXPR_ARGX);
	case E_EQUAL:
		return expr_calculate_pexpr_y_equals(e, data);
	case E_UNEQUAL:
		return expr_calculate_pexpr_y_unequals(e, data);
	case E_LTH:
	case E_LEQ:
	case E_GTH:
	case E_GEQ:
		return expr_calculate_pexpr_y_comp(e, data);
	default:
		// TODO
		fprintf(stderr, "Unhandled type - %s", __func__);
		return NULL;
	}
}

/*
 * calculate, when expr will evaluate to yes
 */
struct pexpr *expr_calculate_pexpr_y(struct expr *e, struct cfdata *data)
{
	if (!e)
		return NULL;

	switch (e->type) {
	case E_SYMBOL:
		return pexpr_alloc_symbol(e->left.sym->fexpr_y);
	case E_AND:
		return expr_calculate_pexpr_y_and(e->left.expr, e->right.expr,
						  data);
	case E_OR:
		return expr_calculate_pexpr_y_or(e->left.expr, e->right.expr,
						 data);
	case E_NOT:
		return expr_calculate_pexpr_y_not(e->left.expr, data);
	case E_EQUAL:
		return expr_calculate_pexpr_y_equals(e, data);
	case E_UNEQUAL:
		return expr_calculate_pexpr_y_unequals(e, data);
	case E_LTH:
	case E_LEQ:
	case E_GTH:
	case E_GEQ:
		return expr_calculate_pexpr_y_comp(e, data);
	default:
		fprintf(stderr, "Unhandled type - %s", __func__);
		return NULL;
	}
}

/*
 * calculate, when expr will evaluate to mod
 */
struct pexpr *expr_calculate_pexpr_m(struct expr *e, struct cfdata *data)
{
	if (!e)
		return NULL;

	if (!expr_can_evaluate_to_mod(e))
		return pexpr_alloc_symbol(data->constants->const_false);

	switch (e->type) {
	case E_SYMBOL:
		return pexpr_alloc_symbol(e->left.sym->fexpr_m);
	case E_AND:
		return expr_calculate_pexpr_m_and(e->left.expr, e->right.expr,
						  data);
	case E_OR:
		return expr_calculate_pexpr_m_or(e->left.expr, e->right.expr,
						 data);
	case E_NOT:
		return expr_calculate_pexpr_m_not(e->left.expr, data);
	default:
		perror("Trying to evaluate to mod.");
		return NULL;
	}
}

/*
 * calculate, when expr of type AND will evaluate to yes
 * A && B
 */
struct pexpr *expr_calculate_pexpr_y_and(struct expr *a, struct expr *b,
					 struct cfdata *data)
{
	return pexpr_and(expr_calculate_pexpr_y(a, data),
			      expr_calculate_pexpr_y(b, data), data,
			      PEXPR_ARGX);
}

/*
 * calculate, when expr of type AND will evaluate to mod
 * (A || A_m) && (B || B_m) && !(A && B)
 */
struct pexpr *expr_calculate_pexpr_m_and(struct expr *a, struct expr *b,
					 struct cfdata *data)
{
	struct pexpr *topright =
		pexpr_not(pexpr_and(expr_calculate_pexpr_y(a, data),
					      expr_calculate_pexpr_y(b, data),
					      data, PEXPR_ARGX),
			       data);
	struct pexpr *ll_left = pexpr_or(expr_calculate_pexpr_y(a, data),
					 expr_calculate_pexpr_m(a, data), data,
					 PEXPR_ARGX);
	struct pexpr *ll_right = pexpr_or(expr_calculate_pexpr_y(b, data),
					  expr_calculate_pexpr_m(b, data), data,
					  PEXPR_ARGX);
	struct pexpr *topleft = pexpr_and(ll_left, ll_right, data, PEXPR_ARGX);

	return pexpr_and(topleft, topright, data, PEXPR_ARGX);
}

/*
 * calculate, when expr of type AND will evaluate to mod or yes
 * (A || A_m) && (B || B_m)
 */
struct pexpr *expr_calculate_pexpr_both_and(struct expr *a, struct expr *b,
					    struct cfdata *data)
{
	struct pexpr *left = pexpr_or(expr_calculate_pexpr_y(a, data),
				      expr_calculate_pexpr_m(a, data), data,
				      PEXPR_ARGX);
	struct pexpr *right = pexpr_or(expr_calculate_pexpr_y(b, data),
				       expr_calculate_pexpr_m(b, data), data,
				       PEXPR_ARGX);

	return pexpr_and(left, right, data, PEXPR_ARGX);
}

/*
 * calculate, when expr of type OR will evaluate to yes
 * A || B
 */
struct pexpr *expr_calculate_pexpr_y_or(struct expr *a, struct expr *b,
					struct cfdata *data)
{
	return pexpr_or(expr_calculate_pexpr_y(a, data),
			     expr_calculate_pexpr_y(b, data), data, PEXPR_ARGX);
}

/*
 * calculate, when expr of type OR will evaluate to mod
 * (A_m || B_m) && !A && !B
 */
struct pexpr *expr_calculate_pexpr_m_or(struct expr *a, struct expr *b,
					struct cfdata *data)
{
	struct pexpr *topright =
		pexpr_not(expr_calculate_pexpr_y(b, data), data);
	struct pexpr *lowerleft = pexpr_or(expr_calculate_pexpr_m(a, data),
						expr_calculate_pexpr_m(b, data),
						data, PEXPR_ARGX);
	struct pexpr *topleft = pexpr_and(
		lowerleft,
		pexpr_not(expr_calculate_pexpr_y(a, data), data), data,
		PEXPR_ARGX);

	return pexpr_and(topleft, topright, data, PEXPR_ARGX);
}

/*
 * calculate, when expr of type OR will evaluate to mod or yes
 * (A_m || A || B_m || B)
 */
struct pexpr *expr_calculate_pexpr_both_or(struct expr *a, struct expr *b,
					   struct cfdata *data)
{
	struct pexpr *left = pexpr_or(expr_calculate_pexpr_y(a, data),
				      expr_calculate_pexpr_m(a, data), data,
				      PEXPR_ARGX);
	struct pexpr *right = pexpr_or(expr_calculate_pexpr_y(b, data),
				       expr_calculate_pexpr_m(b, data), data,
				       PEXPR_ARGX);

	return pexpr_or(left, right, data, PEXPR_ARGX);
}

/*
 * calculate, when expr of type NOT will evaluate to yes
 * !(A || A_m)
 */
struct pexpr *expr_calculate_pexpr_y_not(struct expr *e, struct cfdata *data)
{
	return pexpr_not(pexpr_or(expr_calculate_pexpr_y(e, data),
					    expr_calculate_pexpr_m(e, data),
					    data, PEXPR_ARGX),
			      data);
}

/*
 * calculate, when expr of type NOT will evaluate to mod
 * A_m
 */
struct pexpr *expr_calculate_pexpr_m_not(struct expr *e, struct cfdata *data)
{
	return expr_calculate_pexpr_m(e, data);
}

static struct pexpr *equiv_pexpr_share(struct pexpr *a, struct pexpr *b,
				       struct cfdata *data)
{
	struct pexpr *yes = pexpr_and_share(a, b, data);
	struct pexpr *not = pexpr_and(pexpr_not_share(a, data),
					   pexpr_not_share(b, data), data,
					   PEXPR_ARGX);

	return pexpr_or(yes, not, data, PEXPR_ARGX);
}

static struct pexpr *equiv_pexpr_move(struct pexpr *a, struct pexpr *b,
				       struct cfdata *data,
				       enum pexpr_move move)
{
	return pexpr_move_wrapper(a, b, data, move, equiv_pexpr_share);
}

/*
 * create the fexpr of a non-boolean symbol for a specific value
 */
struct fexpr *sym_create_nonbool_fexpr(struct symbol *sym, char *value,
				       struct cfdata *data)
{
	struct fexpr *e;
	char *s;
	struct fexpr_node *first =
		list_first_entry(&sym->nb_vals->list, struct fexpr_node, node);

	if (!strcmp(value, "")) {
		if (sym->type == S_STRING)
			return list_next_entry(first, node)->elem;
		else
			return first->elem;
	}

	e = sym_get_nonbool_fexpr(sym, value);

	/* fexpr already exists */
	if (e != NULL)
		return e;

	s = value;
	if (sym->type == S_INT && !string_is_number(value)) {
		struct symbol *tmp = sym_find(value);

		if (tmp != NULL)
			s = (char *) tmp->curr.val;
	} else if (sym->type == S_HEX && !string_is_hex(value)) {
		struct symbol *tmp = sym_find(value);

		if (tmp != NULL)
			s = (char *) tmp->curr.val;
	} else if (sym->type == S_STRING) {
		struct symbol *tmp = sym_find(value);

		if (tmp != NULL)
			s = (char *) tmp->curr.val;
	}

	if (!strcmp(s, "")) {
		if (sym->type == S_STRING)
			return list_next_entry(first, node)->elem;
		else
			return first->elem;
	}

	e = sym_get_nonbool_fexpr(sym, s);
	if (e != NULL)
		return e;

	e = fexpr_create(data->sat_variable_nr++, FE_NONBOOL, sym->name);
	e->sym = sym;
	str_append(&e->name, "=");
	str_append(&e->name, s);
	e->nb_val = str_new();
	str_append(&e->nb_val, s);

	CF_PUSH_BACK(sym->nb_vals, e, fexpr);
	fexpr_add_to_satmap(e, data);

	return e;
}

/*
 * return the fexpr of a non-boolean symbol for a specific value, NULL if
 * non-existent
 */
struct fexpr *sym_get_nonbool_fexpr(struct symbol *sym, char *value)
{
	struct fexpr_node *e;

	CF_LIST_FOR_EACH(e, sym->nb_vals, fexpr) {
		if (strcmp(str_get(&e->elem->nb_val), value) == 0)
			return e->elem;
	}

	return NULL;
}

/*
 * return the fexpr of a non-boolean symbol for a specific value, if it exists
 * otherwise create it
 */
struct fexpr *sym_get_or_create_nonbool_fexpr(struct symbol *sym, char *value,
					      struct cfdata *data)
{
	struct fexpr *e = sym_get_nonbool_fexpr(sym, value);

	if (e != NULL)
		return e;
	else
		return sym_create_nonbool_fexpr(sym, value, data);
}

/*
 * calculate, when expr of type EQUAL will evaluate to yes
 * Side effect: May create certain values in e->{left,right}.sym->nb_vals
 */
struct pexpr *expr_calculate_pexpr_y_equals(struct expr *e, struct cfdata *data)
{
	/* comparing 2 tristate constants */
	if (sym_is_tristate_constant(e->left.sym) &&
	    sym_is_tristate_constant(e->right.sym))
		return e->left.sym == e->right.sym ?
			       pexpr_alloc_symbol(data->constants->const_true) :
			       pexpr_alloc_symbol(data->constants->const_false);

	/* comparing 2 nonboolean constants */
	if (sym_is_nonbool_constant(e->left.sym) &&
	    sym_is_nonbool_constant(e->right.sym))
		return strcmp(e->left.sym->name, e->right.sym->name) == 0 ?
			       pexpr_alloc_symbol(data->constants->const_true) :
			       pexpr_alloc_symbol(data->constants->const_false);

	/* comparing 2 boolean/tristate incl. yes/mod/no constants */
	if (sym_is_bool_or_triconst(e->left.sym) &&
	    sym_is_bool_or_triconst(e->right.sym)) {
		struct pexpr *yes = equiv_pexpr_move(
			pexpr_alloc_symbol(e->left.sym->fexpr_y),
			pexpr_alloc_symbol(e->right.sym->fexpr_y), data,
			PEXPR_ARGX);
		struct pexpr *mod = equiv_pexpr_move(
			pexpr_alloc_symbol(e->left.sym->fexpr_m),
			pexpr_alloc_symbol(e->right.sym->fexpr_m), data,
			PEXPR_ARGX);

		return pexpr_and(yes, mod, data, PEXPR_ARGX);
	}

	/* comparing nonboolean with a constant */
	if (sym_is_nonboolean(e->left.sym) &&
	    sym_is_nonbool_constant(e->right.sym))
		return pexpr_alloc_symbol(sym_get_or_create_nonbool_fexpr(
			e->left.sym, e->right.sym->name, data));

	if (sym_is_nonbool_constant(e->left.sym) &&
	    sym_is_nonboolean(e->right.sym))
		return pexpr_alloc_symbol(sym_get_or_create_nonbool_fexpr(
			e->right.sym, e->left.sym->name, data));

	/* comparing nonboolean with tristate constant, will never be true */
	if (sym_is_nonboolean(e->left.sym) &&
	    sym_is_tristate_constant(e->right.sym))
		return pexpr_alloc_symbol(data->constants->const_false);
	if (sym_is_tristate_constant(e->left.sym) &&
	    sym_is_nonboolean(e->right.sym))
		return pexpr_alloc_symbol(data->constants->const_false);

	/* comparing 2 nonboolean symbols */
	if (sym_is_nonboolean(e->left.sym) && sym_is_nonboolean(e->right.sym)) {
		struct pexpr *c =
			pexpr_alloc_symbol(data->constants->const_false);
		struct fexpr *e1, *e2;
		struct fexpr_node *node1, *node2;
		bool first1 = true;

		CF_LIST_FOR_EACH(node1, e->left.sym->nb_vals, fexpr) {
			bool first2 = true;

			if (first1) {
				first1 = false;
				continue;
			}
			e1 = node1->elem;
			CF_LIST_FOR_EACH(node2, e->right.sym->nb_vals, fexpr)
			{
				if (first2) {
					first2 = false;
					continue;
				}

				e2 = node2->elem;
				if (!strcmp(str_get(&e1->nb_val),
					    str_get(&e2->nb_val))) {
					c = pexpr_or(
						c,
						pexpr_and(
							pexpr_alloc_symbol(e1),
							pexpr_alloc_symbol(e2),
							data, PEXPR_ARGX),
						data, PEXPR_ARGX);
					break;
				}
			}
		}
		return c;
	}

	/*
	 * comparing boolean item with nonboolean constant, will never be true
	 */
	if (sym_is_tristate_constant(e->left.sym) &&
	    sym_is_nonbool_constant(e->right.sym))
		return pexpr_alloc_symbol(data->constants->const_false);
	if (sym_is_nonbool_constant(e->left.sym) &&
	    sym_is_tristate_constant(e->right.sym))
		return pexpr_alloc_symbol(data->constants->const_false);

	/* comparing symbol of type unknown with tristate constant */
	if (e->left.sym->type == S_UNKNOWN &&
	    sym_is_tristate_constant(e->right.sym))
		return pexpr_alloc_symbol(data->constants->const_false);
	if (sym_is_tristate_constant(e->left.sym) &&
	    e->right.sym->type == S_UNKNOWN)
		return pexpr_alloc_symbol(data->constants->const_false);

	/* any other comparison is not supported and should not be executed */
	fprintf(stderr, "Unsupported equality in:");
	expr_fprint(e, stderr);

	return pexpr_alloc_symbol(data->constants->const_false);
}

/*
 * transform an UNEQUAL into a Not(EQUAL)
 */
struct pexpr *expr_calculate_pexpr_y_unequals(struct expr *e,
					      struct cfdata *data)
{
	return pexpr_not(expr_calculate_pexpr_y_equals(e, data), data);
}

struct pexpr *expr_calculate_pexpr_y_comp(struct expr *e, struct cfdata *data)
{
	if (!e)
		return NULL;

	switch (e->type) {
	case E_LTH:
	case E_LEQ:
	case E_GTH:
	case E_GEQ:
		/* compare non-Boolean symbol with constant */
		if (sym_is_nonboolean(e->left.sym) &&
			e->right.sym->type == S_UNKNOWN &&
			string_is_number(e->right.sym->name)
		) {
			return expr_eval_unequal_nonbool_const(
				e->left.sym, e->right.sym, e->type, data);
		}
		if (sym_is_nonboolean(e->right.sym) &&
			e->left.sym->type == S_UNKNOWN &&
			string_is_number(e->left.sym->name)
		) {
			return expr_eval_unequal_nonbool_const(
				e->right.sym, e->left.sym, e->type, data);
		}

		/* compare 2 Boolean symbols */
		if (sym_is_boolean(e->left.sym) && sym_is_boolean(e->right.sym))
			return expr_eval_unequal_bool(e->left.sym, e->right.sym,
						      e->type, data);

		return pexpr_alloc_symbol(data->constants->const_false);
	default:
		fprintf(stderr, "Unhandled type - %s", __func__);
		return NULL;
	}
}

static struct pexpr *pexpr_move_wrapper(
	struct pexpr *a, struct pexpr *b, struct cfdata *data,
	enum pexpr_move move,
	struct pexpr *(*func)(struct pexpr *, struct pexpr *, struct cfdata *))
{
	struct pexpr *retval = func(a, b, data);

	switch (move) {
	case PEXPR_ARG1:
		pexpr_put(a);
		break;
	case PEXPR_ARG2:
		pexpr_put(b);
		break;
	case PEXPR_ARGX:
		pexpr_put(a);
		pexpr_put(b);
		break;
	default:
		fprintf(stderr, "%s: invalid value for @move - %d\n", __func__,
			move);
	}
	return retval;
}

struct pexpr *pexpr_and(struct pexpr *a, struct pexpr *b, struct cfdata *data,
			enum pexpr_move move)
{
	return pexpr_move_wrapper(a, b, data, move, pexpr_and_share);
}

/*
 * macro to create a pexpr of type AND
 */
struct pexpr *pexpr_and_share(struct pexpr *a, struct pexpr *b,
			      struct cfdata *data)
{
	struct pexpr *e;

	/* A && A -> A */
	if (a == b || pexpr_test_eq(a, b, data)) {
		pexpr_get(a);
		return a;
	}

	/* simplifications:
	 * expr && False -> False
	 * expr && True  -> expr
	 */
	if ((a->type == PE_SYMBOL &&
	     a->left.fexpr == data->constants->const_false) ||
	    (b->type == PE_SYMBOL &&
	     b->left.fexpr == data->constants->const_true)) {
		pexpr_get(a);
		return a;
	}

	if ((b->type == PE_SYMBOL &&
	     b->left.fexpr == data->constants->const_false) ||
	    (a->type == PE_SYMBOL &&
	     a->left.fexpr == data->constants->const_true)) {
		pexpr_get(b);
		return b;
	}

	/* (A && B) && C -> A && B if B == C */
	if (a->type == PE_AND && pexpr_test_eq(a->right.pexpr, b, data)) {
		pexpr_get(a);
		return a;
	}

	/* A && (B && C) -> B && C if A == B */
	if (b->type == PE_AND && pexpr_test_eq(a, b->left.pexpr, data)) {
		pexpr_get(b);
		return b;
	}

	if (a->type == PE_OR && b->type == PE_OR) {
		e = NULL;
		/* (A || B) && (C || D) -> A || (B && D) if A == C */
		if (pexpr_test_eq(a->left.pexpr, b->left.pexpr, data)) {
			e = pexpr_or(a->left.pexpr,
					  pexpr_and_share(a->right.pexpr,
							  b->right.pexpr, data),
					  data, PEXPR_ARG2);
		}
		/* (A || B) && (C || D) -> B || (A && C) if B == D */
		else if (pexpr_test_eq(a->right.pexpr, b->right.pexpr, data)) {
			e = pexpr_or(a->right.pexpr,
					  pexpr_and_share(a->left.pexpr,
							  b->left.pexpr, data),
					  data, PEXPR_ARG2);
		}
		/* (A || B) && (C || D) -> A || (B && C) if A == D */
		else if (pexpr_test_eq(a->left.pexpr, b->right.pexpr, data)) {
			e = pexpr_or(a->left.pexpr,
					  pexpr_and_share(a->right.pexpr,
							  b->left.pexpr, data),
					  data, PEXPR_ARG2);
		}
		/* (A || B) && (C || D) -> B || (A && D) if B == C */
		else if (pexpr_test_eq(a->right.pexpr, b->left.pexpr, data)) {
			e = pexpr_or(a->right.pexpr,
					  pexpr_and_share(a->left.pexpr,
							  b->right.pexpr, data),
					  data, PEXPR_ARG2);
		}
		if (e)
			return e;
	}

	/* general case */
	e = xmalloc(sizeof(*e));
	pexpr_get(a);
	pexpr_get(b);
	pexpr_construct_and(e, a, b, 1);
	return e;
}

struct pexpr *pexpr_or(struct pexpr *a, struct pexpr *b, struct cfdata *data,
		       enum pexpr_move move)
{
	return pexpr_move_wrapper(a, b, data, move, pexpr_or_share);
}

/*
 * macro to create a pexpr of type OR
 */
struct pexpr *pexpr_or_share(struct pexpr *a, struct pexpr *b,
			     struct cfdata *data)
{
	struct pexpr *e;
	bool cond1, cond2;

	/* A || A  -> A */
	if (a == b || pexpr_test_eq(a, b, data)) {
		pexpr_get(a);
		return a;
	}

	/* simplifications:
	 * A || False -> A
	 * A || True  -> True
	 */
	cond1 = a->type == PE_SYMBOL &&
		a->left.fexpr == data->constants->const_false;
	cond2 = b->type == PE_SYMBOL &&
		b->left.fexpr == data->constants->const_true;
	if (cond1 || cond2) {
		pexpr_get(b);
		return b;
	}
	cond1 = b->type == PE_SYMBOL &&
		b->left.fexpr == data->constants->const_false;
	cond2 = a->type == PE_SYMBOL &&
		a->left.fexpr == data->constants->const_true;
	if (cond1 || cond2) {
		pexpr_get(a);
		return a;
	}

	/* A || (B && C) -> A if (A == B || A == C) */
	if (b->type == PE_AND && (pexpr_test_eq(a, b->left.pexpr, data) ||
				  pexpr_test_eq(a, b->right.pexpr, data))) {
		pexpr_get(a);
		return a;
	}
	/* (A && B) || C -> C if (A == C || B == C) */
	if (a->type == PE_AND && (pexpr_test_eq(a->left.pexpr, b, data) ||
				  pexpr_test_eq(a->right.pexpr, b, data))) {
		pexpr_get(b);
		return b;
	}

	/* -A || B -> True if A == B
	 * A || -B -> True if A == B
	 */
	cond1 = a->type == PE_NOT && pexpr_test_eq(a->left.pexpr, b, data);
	cond2 = b->type == PE_NOT && pexpr_test_eq(a, b->left.pexpr, data);
	if (cond1 || cond2)
		return pexpr_alloc_symbol(data->constants->const_true);

	if (a->type == PE_AND && b->type == PE_AND) {
		e = NULL;
		/* (A && B) || (C && D) -> A && (B || D) if (A == C) */
		if (pexpr_test_eq(a->left.pexpr, b->left.pexpr, data)) {
			e = pexpr_and(a->left.pexpr,
				      pexpr_or_share(a->right.pexpr,
						     b->right.pexpr, data),
				      data, PEXPR_ARG2);
		}
		/* (A && B) || (C && D) -> B && (A || C) if (B == D) */
		if (pexpr_test_eq(a->right.pexpr, b->right.pexpr, data)) {
			e = pexpr_and(a->right.pexpr,
				      pexpr_or_share(a->left.pexpr,
						     b->left.pexpr, data),
				      data, PEXPR_ARG2);
		}
		/* (A && B) || (C && D) -> A && (B || C) if (A == D) */
		if (pexpr_test_eq(a->left.pexpr, b->right.pexpr, data)) {
			e = pexpr_and(a->left.pexpr,
				      pexpr_or_share(a->right.pexpr,
						     b->left.pexpr, data),
				      data, PEXPR_ARG2);
		}
		/* (A && B) || (C && D) -> B && (A || D) if (B == C) */
		if (pexpr_test_eq(a->right.pexpr, b->left.pexpr, data)) {
			e = pexpr_and(a->right.pexpr,
				      pexpr_or_share(a->left.pexpr,
						     b->right.pexpr, data),
				      data, PEXPR_ARG2);
		}
		if (e)
			return e;
	}

	/* (A && B) || (C || D) -> C || D if
	 * A == C || A == D || B == C || B == D
	 */
	if (a->type == PE_AND && b->type == PE_OR &&
	    (pexpr_test_eq(a->left.pexpr, b->left.pexpr, data) ||
	     pexpr_test_eq(a->left.pexpr, b->right.pexpr, data) ||
	     pexpr_test_eq(a->right.pexpr, b->left.pexpr, data) ||
	     pexpr_test_eq(a->right.pexpr, b->right.pexpr, data))) {
		pexpr_get(b);
		return b;
	}
	/* (C || D) || (A && B) -> C || D if
	 * A == C || A == D || B == C || B == D
	 */
	if (a->type == PE_OR && b->type == PE_AND &&
	    (pexpr_test_eq(a->left.pexpr, b->left.pexpr, data) ||
	     pexpr_test_eq(a->left.pexpr, b->right.pexpr, data) ||
	     pexpr_test_eq(a->right.pexpr, b->left.pexpr, data) ||
	     pexpr_test_eq(a->right.pexpr, b->right.pexpr, data))) {
		pexpr_get(a);
		return a;
	}

	/* general case */
	e = xmalloc(sizeof(*e));
	pexpr_get(a);
	pexpr_get(b);
	pexpr_construct_or(e, a, b, 1);

	return e;
}

struct pexpr *pexpr_not(struct pexpr *a, struct cfdata *data)
{
	struct pexpr *retval = pexpr_not_share(a, data);

	pexpr_put(a);
	return retval;
}

/*
 * Builds NOT(@a)
 */
struct pexpr *pexpr_not_share(struct pexpr *a, struct cfdata *data)
{
	struct pexpr *ret_val;

	if (a->type == PE_SYMBOL &&
	    a->left.fexpr == data->constants->const_false)
		ret_val = pexpr_alloc_symbol(data->constants->const_true);
	else if (a->type == PE_SYMBOL &&
	    a->left.fexpr == data->constants->const_true)
		ret_val = pexpr_alloc_symbol(data->constants->const_false);
	/* eliminate double negation */
	else if (a->type == PE_NOT) {
		ret_val = a->left.pexpr;
		pexpr_get(ret_val);
	}
	/* De Morgan */
	else if (a->type == PE_AND) {
		ret_val = xmalloc(sizeof(*ret_val));
		pexpr_construct_or(ret_val,
				   pexpr_not_share(a->left.pexpr, data),
				   pexpr_not_share(a->right.pexpr, data), 1);
	} else if (a->type == PE_OR) {
		ret_val = xmalloc(sizeof(*ret_val));
		pexpr_construct_and(ret_val,
				    pexpr_not_share(a->left.pexpr, data),
				    pexpr_not_share(a->right.pexpr, data), 1);
	} else {
		ret_val = xmalloc(sizeof(*ret_val));
		pexpr_get(a);
		pexpr_construct_not(ret_val, a, 1);
	}

	return ret_val;
}

struct pexpr *pexpr_implies(struct pexpr *a, struct pexpr *b,
			    struct cfdata *data, enum pexpr_move move)
{
	return pexpr_move_wrapper(a, b, data, move, pexpr_implies_share);
}

/*
 * macro to construct a pexpr for "A implies B"
 */
struct pexpr *pexpr_implies_share(struct pexpr *a, struct pexpr *b,
				  struct cfdata *data)
{
	/* A => B -> True if A == B */
	if (a == b || pexpr_test_eq(a, b, data))
		return pexpr_alloc_symbol(data->constants->const_true);

	/* (A => B && C) -> (A => C) if A == B */
	if (b->type == PE_AND && pexpr_test_eq(a, b->left.pexpr, data))
		return pexpr_implies_share(a, b->right.pexpr, data);
	/* (A => B && C) -> (A => B) if A == C */
	if (b->type == PE_AND && pexpr_test_eq(a, b->right.pexpr, data))
		return pexpr_implies_share(a, b->left.pexpr, data);

	/* (A => B || C) -> True if (A == B || A == C) */
	if (b->type == PE_OR && (pexpr_test_eq(a, b->left.pexpr, data) ||
				 pexpr_test_eq(a, b->right.pexpr, data)))
		return pexpr_alloc_symbol(data->constants->const_true);

	/* (A && B => C) -> True if (A == C || B == C) */
	if (a->type == PE_AND && (pexpr_test_eq(a->left.pexpr, b, data) ||
				  pexpr_test_eq(a->right.pexpr, b, data)))
		return pexpr_alloc_symbol(data->constants->const_true);

	return pexpr_or(pexpr_not_share(a, data), b, data, PEXPR_ARG1);
}

/*
 * check whether a pexpr is in CNF
 */
bool pexpr_is_cnf(struct pexpr *e)
{
	if (!e)
		return false;

	switch (e->type) {
	case PE_SYMBOL:
		return true;
	case PE_AND:
		return false;
	case PE_OR:
		return pexpr_is_cnf(e->left.pexpr) &&
		       pexpr_is_cnf(e->right.pexpr);
	case PE_NOT:
		return e->left.pexpr->type == PE_SYMBOL;
	}

	return false;
}

/*
 * check whether a pexpr is in NNF
 */
bool pexpr_is_nnf(struct pexpr *e)
{
	if (!e)
		return false;

	switch (e->type) {
	case PE_SYMBOL:
		return true;
	case PE_AND:
	case PE_OR:
		return pexpr_is_nnf(e->left.pexpr) &&
		       pexpr_is_nnf(e->right.pexpr);
	case PE_NOT:
		return e->left.pexpr->type == PE_SYMBOL;
	}

	return false;
}

/*
 * return fexpr_both for a symbol
 */
struct pexpr *sym_get_fexpr_both(struct symbol *sym, struct cfdata *data)
{
	return sym->type == S_TRISTATE ?
		       pexpr_or(pexpr_alloc_symbol(sym->fexpr_m),
				pexpr_alloc_symbol(sym->fexpr_y), data,
				PEXPR_ARGX) :
		       pexpr_alloc_symbol(sym->fexpr_y);
}

/*
 * return fexpr_sel_both for a symbol
 */
struct pexpr *sym_get_fexpr_sel_both(struct symbol *sym, struct cfdata *data)
{
	if (!sym->rev_dep.expr)
		return pexpr_alloc_symbol(data->constants->const_false);

	return sym->type == S_TRISTATE ?
		       pexpr_or(pexpr_alloc_symbol(sym->fexpr_sel_m),
				pexpr_alloc_symbol(sym->fexpr_sel_y), data,
				PEXPR_ARGX) :
		       pexpr_alloc_symbol(sym->fexpr_sel_y);
}

/*
 * check, if the fexpr is a symbol, a True/False-constant, a literal symbolizing
 * a non-boolean or a choice symbol
 */
bool fexpr_is_symbol(struct fexpr *e)
{
	return e->type == FE_SYMBOL || e->type == FE_FALSE ||
	       e->type == FE_TRUE || e->type == FE_NONBOOL ||
	       e->type == FE_CHOICE || e->type == FE_SELECT ||
	       e->type == FE_NPC;
}

/*
 * check whether a pexpr is a symbol or a negated symbol
 */
bool pexpr_is_symbol(struct pexpr *e)
{
	return e->type == PE_SYMBOL ||
	       (e->type == PE_NOT && e->left.pexpr->type == PE_SYMBOL);
}

/*
 * check whether the fexpr is a constant (true/false)
 */
bool fexpr_is_constant(struct fexpr *e, struct cfdata *data)
{
	return e == data->constants->const_true ||
	       e == data->constants->const_false;
}

/*
 * add a fexpr to the satmap
 */
void fexpr_add_to_satmap(struct fexpr *e, struct cfdata *data)
{
	if (e->satval >= data->satmap_size) {
		data->satmap = xrealloc(data->satmap,
					data->satmap_size * 2 *
						sizeof(*data->satmap));
		data->satmap_size *= 2;
	}

	data->satmap[e->satval] = e;
}

/*
 * print a fexpr
 */
void fexpr_print(char *tag, struct fexpr *e)
{
	if (!e)
		return;

	printf("%s: %s\n", tag, str_get(&e->name));
}

/*
 * write an fexpr into a string (format needed for testing)
 */
void fexpr_as_char(struct fexpr *e, struct gstr *s)
{
	if (!e)
		return;

	switch (e->type) {
	case FE_SYMBOL:
	case FE_CHOICE:
	case FE_SELECT:
	case FE_NPC:
	case FE_NONBOOL:
		str_append(s, "definedEx(");
		str_append(s, str_get(&e->name));
		str_append(s, ")");
		return;
	case FE_FALSE:
		str_append(s, "0");
		return;
	case FE_TRUE:
		str_append(s, "1");
		return;
	default:
		return;
	}
}

/*
 * write a pexpr into a string
 */
void pexpr_as_char(struct pexpr *e, struct gstr *s, int parent,
		   struct cfdata *data)
{
	if (!e)
		return;

	switch (e->type) {
	case PE_SYMBOL:
		if (e->left.fexpr == data->constants->const_false) {
			str_append(s, "0");
			return;
		}
		if (e->left.fexpr == data->constants->const_true) {
			str_append(s, "1");
			return;
		}
		str_append(s, "definedEx(");
		str_append(s, str_get(&e->left.fexpr->name));
		str_append(s, ")");
		return;
	case PE_AND:
		if (parent != PE_AND)
			str_append(s, "(");
		pexpr_as_char(e->left.pexpr, s, PE_AND, data);
		str_append(s, " && ");
		pexpr_as_char(e->right.pexpr, s, PE_AND, data);
		if (parent != PE_AND)
			str_append(s, ")");
		return;
	case PE_OR:
		if (parent != PE_OR)
			str_append(s, "(");
		pexpr_as_char(e->left.pexpr, s, PE_OR, data);
		str_append(s, " || ");
		pexpr_as_char(e->right.pexpr, s, PE_OR, data);
		if (parent != PE_OR)
			str_append(s, ")");
		return;
	case PE_NOT:
		str_append(s, "!");
		pexpr_as_char(e->left.pexpr, s, PE_NOT, data);
		return;
	}
}

/*
 * write a pexpr into a string
 */
void pexpr_as_char_short(struct pexpr *e, struct gstr *s, int parent)
{
	if (!e)
		return;

	switch (e->type) {
	case PE_SYMBOL:
		str_append(s, str_get(&e->left.fexpr->name));
		return;
	case PE_AND:
		if (parent != PE_AND)
			str_append(s, "(");
		pexpr_as_char_short(e->left.pexpr, s, PE_AND);
		str_append(s, " && ");
		pexpr_as_char_short(e->right.pexpr, s, PE_AND);
		if (parent != PE_AND)
			str_append(s, ")");
		return;
	case PE_OR:
		if (parent != PE_OR)
			str_append(s, "(");
		pexpr_as_char_short(e->left.pexpr, s, PE_OR);
		str_append(s, " || ");
		pexpr_as_char_short(e->right.pexpr, s, PE_OR);
		if (parent != PE_OR)
			str_append(s, ")");
		return;
	case PE_NOT:
		str_append(s, "!");
		pexpr_as_char_short(e->left.pexpr, s, PE_NOT);
		return;
	}
}

/*
 * check whether a pexpr contains a specific fexpr
 */
bool pexpr_contains_fexpr(struct pexpr *e, struct fexpr *fe)
{
	if (!e)
		return false;

	switch (e->type) {
	case PE_SYMBOL:
		return e->left.fexpr->satval == fe->satval;
	case PE_AND:
	case PE_OR:
		return pexpr_contains_fexpr(e->left.pexpr, fe) ||
			pexpr_contains_fexpr(e->right.pexpr, fe);
	case PE_NOT:
		return e->left.pexpr->left.fexpr->satval == fe->satval;
	}

	return false;
}

/*
 * print a fexpr_list
 */
void fexpr_list_print(char *title, struct fexpr_list *list)
{
	struct fexpr_node *node;
	bool first = true;

	printf("%s: [", title);

	CF_LIST_FOR_EACH(node, list, fexpr) {
		if (first)
			first = false;
		else
			printf(", ");
		printf("%s", str_get(&node->elem->name));
	}

	printf("]\n");
}

/*
 * print a fexl_list
 */
void fexl_list_print(char *title, struct fexl_list *list)
{
	struct fexl_node *node;

	printf("%s:\n", title);

	CF_LIST_FOR_EACH(node, list, fexl)
		fexpr_list_print(":", node->elem);
}

/*
 * print a pexpr_list
 */
void pexpr_list_print(char *title, struct pexpr_list *list)
{
	struct pexpr_node *node;

	printf("%s: [", title);

	CF_LIST_FOR_EACH(node, list, pexpr) {
		pexpr_print_util(node->elem, -1);
		if (node->node.next != &list->list)
			printf(", ");
	}

	printf("]\n");
}

/*
 * free an defm_list (and pexpr_put the conditions of the maps and free the
 * node->element's)
 */
void defm_list_destruct(struct defm_list *list)
{
	struct defm_node *node;

	CF_LIST_FOR_EACH(node, list, defm)
		pexpr_put(node->elem->e);
	CF_LIST_FREE(list, defm);
}

/*
 * free a pexpr_list (and pexpr_put the elements)
 */
void pexpr_list_free_put(struct pexpr_list *list)
{
	struct pexpr_node *node;

	CF_LIST_FOR_EACH(node, list, pexpr)
		pexpr_put(node->elem);
	CF_LIST_FREE(list, pexpr);
}

/*
 * simplify a pexpr in-place
 *	pexpr && False -> False
 *	pexpr && True  -> pexpr
 *	pexpr || False -> pexpr
 *	pexpr || True  -> True
 */
static void pexpr_eliminate_yn(struct pexpr *e, struct cfdata *data)
{
	struct pexpr *tmp;
	unsigned int ref_count;

	if (!e)
		return;

	switch (e->type) {
	case PE_AND:
		pexpr_eliminate_yn(e->left.pexpr, data);
		pexpr_eliminate_yn(e->right.pexpr, data);
		if (e->left.pexpr->type == PE_SYMBOL) {
			if (e->left.pexpr->left.fexpr ==
			    data->constants->const_false) {
				pexpr_put(e->left.pexpr);
				pexpr_put(e->right.pexpr);
				ref_count = e->ref_count;
				pexpr_construct_sym(
					e, data->constants->const_false,
					ref_count);
				return;
			} else if (e->left.pexpr->left.fexpr ==
				   data->constants->const_true) {
				pexpr_put(e->left.pexpr);
				tmp = e->right.pexpr;
				ref_count = e->ref_count;
				pexpr_shallow_copy(e, tmp, ref_count);
				pexpr_put(tmp);
				return;
			}
		}
		if (e->right.pexpr->type == PE_SYMBOL) {
			if (e->right.pexpr->left.fexpr ==
			    data->constants->const_false) {
				pexpr_put(e->left.pexpr);
				pexpr_put(e->right.pexpr);
				ref_count = e->ref_count;
				pexpr_construct_sym(
					e, data->constants->const_false,
					ref_count);
				return;
			} else if (e->right.pexpr->left.fexpr ==
				   data->constants->const_true) {
				pexpr_put(e->right.pexpr);
				tmp = e->left.pexpr;
				ref_count = e->ref_count;
				pexpr_shallow_copy(e, tmp, ref_count);
				pexpr_put(tmp);
				return;
			}
		}
		break;
	case PE_OR:
		pexpr_eliminate_yn(e->left.pexpr, data);
		pexpr_eliminate_yn(e->right.pexpr, data);
		if (e->left.pexpr->type == PE_SYMBOL) {
			if (e->left.pexpr->left.fexpr ==
			    data->constants->const_false) {
				pexpr_put(e->left.pexpr);
				tmp = e->right.pexpr;
				ref_count = e->ref_count;
				pexpr_shallow_copy(e, tmp, ref_count);
				pexpr_put(tmp);
				return;
			} else if (e->left.pexpr->left.fexpr ==
				   data->constants->const_true) {
				pexpr_put(e->left.pexpr);
				pexpr_put(e->right.pexpr);
				ref_count = e->ref_count;
				pexpr_construct_sym(
					e, data->constants->const_true,
					ref_count);
				return;
			}
		}
		if (e->right.pexpr->type == PE_SYMBOL) {
			if (e->right.pexpr->left.fexpr ==
			    data->constants->const_false) {
				pexpr_put(e->right.pexpr);
				tmp = e->left.pexpr;
				ref_count = e->ref_count;
				pexpr_shallow_copy(e, tmp, ref_count);
				pexpr_put(tmp);
				return;
			} else if (e->right.pexpr->left.fexpr ==
				   data->constants->const_true) {
				pexpr_put(e->left.pexpr);
				pexpr_put(e->right.pexpr);
				ref_count = e->ref_count;
				pexpr_construct_sym(e,
						    data->constants->const_true,
						    ref_count);
				return;
			}
		}
	default:
		break;
	}
}

static void pexpr_shallow_copy(struct pexpr *dest, struct pexpr *org,
			       unsigned int ref_count)
{
	struct pexpr inter;

	inter.type = org->type;
	inter.left = org->left;
	inter.right = org->right;
	if (org->type == PE_OR || org->type == PE_AND) {
		pexpr_get(org->left.pexpr);
		pexpr_get(org->right.pexpr);
	} else if (org->type == PE_NOT) {
		pexpr_get(org->left.pexpr);
	}
	inter.ref_count = ref_count;
	*dest = inter;
}

/*
 * copy a pexpr
 */
struct pexpr *pexpr_deep_copy(const struct pexpr *org)
{
	struct pexpr *e;

	if (!org)
		return NULL;

	e = xmalloc(sizeof(*org));
	memcpy(e, org, sizeof(*org));
	e->ref_count = 1;
	switch (org->type) {
	case PE_SYMBOL:
		e->left = org->left;
		break;
	case PE_AND:
	case PE_OR:
		e->left.pexpr = pexpr_deep_copy(org->left.pexpr);
		e->right.pexpr = pexpr_deep_copy(org->right.pexpr);
		break;
	case PE_NOT:
		e->left.pexpr = pexpr_deep_copy(org->left.pexpr);
		break;
	}

	return e;
}

/*
 * free a pexpr
 */
void pexpr_free_depr(struct pexpr *e)
{
	if (!e)
		return;

	switch (e->type) {
	case PE_SYMBOL:
		break;
	case PE_AND:
	case PE_OR:
		pexpr_free_depr(e->left.pexpr);
		pexpr_free_depr(e->right.pexpr);
		break;
	case PE_NOT:
		pexpr_free_depr(e->left.pexpr);
		break;
	}

	free(e);
}

/*
 * Increments ref_count and returns @e
 */
struct pexpr *pexpr_get(struct pexpr *e)
{
	++e->ref_count;
	return e;
}

/*
 * Decrements ref_count and if it becomes 0, it recursively puts the references
 * to its children and calls ``free(e)``. If @e == NULL, it does nothing.
 */
void pexpr_put(struct pexpr *e)
{
	if (!e)
		return;

	if (e->ref_count == 0) {
		printd("Invalid call to %s - ref_count is zero\n", __func__);
		return;
	}

	--e->ref_count;
	if (e->ref_count > 0)
		return;

	switch (e->type) {
	case PE_SYMBOL:
		break;
	case PE_AND:
	case PE_OR:
		pexpr_put(e->left.pexpr);
		pexpr_put(e->right.pexpr);
		break;
	case PE_NOT:
		pexpr_put(e->left.pexpr);
		break;
	}

	free(e);
}

/*
 * calls pexpr_put for a NULL-terminated array of struct pexpr *
 */
void _pexpr_put_list(struct pexpr **es)
{
	for (; *es != NULL; es++)
		pexpr_put(*es);
}

#define e1 (*ep1)
#define e2 (*ep2)
/*
 * pexpr_eliminate_eq() helper
 */
static void __pexpr_eliminate_eq(enum pexpr_type type, struct pexpr **ep1,
				 struct pexpr **ep2, struct cfdata *data)
{
	/* recurse down to the leaves */
	if (e1->type == type) {
		__pexpr_eliminate_eq(type, &e1->left.pexpr, &e2, data);
		__pexpr_eliminate_eq(type, &e1->right.pexpr, &e2, data);
		return;
	}
	if (e2->type == type) {
		__pexpr_eliminate_eq(type, &e1, &e2->left.pexpr, data);
		__pexpr_eliminate_eq(type, &e1, &e2->right.pexpr, data);
		return;
	}

	/* e1 and e2 are leaves. Compare them. */
	if (e1->type == PE_SYMBOL && e2->type == PE_SYMBOL &&
	    e1->left.fexpr->satval == e2->left.fexpr->satval &&
	    (e1->left.fexpr == data->constants->const_true ||
	     e2->left.fexpr == data->constants->const_false))
		return;
	if (!pexpr_test_eq(e1, e2, data))
		return;

	/* e1 and e2 are equal leaves. Prepare them for elimination. */
	trans_count++;
	pexpr_put(e1);
	pexpr_put(e2);
	switch (type) {
	case PE_AND:
		e1 = pexpr_alloc_symbol(data->constants->const_true);
		e2 = pexpr_alloc_symbol(data->constants->const_true);
		break;
	case PE_OR:
		e1 = pexpr_alloc_symbol(data->constants->const_false);
		e2 = pexpr_alloc_symbol(data->constants->const_false);
		break;
	default:
		break;
	}
}

/*
 * rewrite pexpr ep1 and ep2 to remove operands common to both
 */
static void pexpr_eliminate_eq(struct pexpr **ep1, struct pexpr **ep2,
			       struct cfdata *data)
{
	if (!e1 || !e2)
		return;

	switch (e1->type) {
	case PE_AND:
	case PE_OR:
		__pexpr_eliminate_eq(e1->type, ep1, ep2, data);
	default:
		break;
	}
	if (e1->type != e2->type)
		switch (e2->type) {
		case PE_AND:
		case PE_OR:
			__pexpr_eliminate_eq(e2->type, ep1, ep2, data);
		default:
			break;
		}
	pexpr_eliminate_yn(e1, data);
	pexpr_eliminate_yn(e2, data);
}
#undef e1
#undef e2

/*
 * check whether 2 pexpr are equal
 */
bool pexpr_test_eq(struct pexpr *e1, struct pexpr *e2, struct cfdata *data)
{
	bool res;
	int old_count;

	if (!e1 || !e2)
		return false;

	if (e1->type != e2->type)
		return false;

	switch (e1->type) {
	case PE_SYMBOL:
		return e1->left.fexpr->satval == e2->left.fexpr->satval;
	case PE_AND:
	case PE_OR:
		e1 = pexpr_deep_copy(e1);
		e2 = pexpr_deep_copy(e2);
		old_count = trans_count;
		pexpr_eliminate_eq(&e1, &e2, data);
		res = (e1->type == PE_SYMBOL && e2->type == PE_SYMBOL &&
			e1->left.fexpr->satval == e2->left.fexpr->satval);
		pexpr_put(e1);
		pexpr_put(e2);
		trans_count = old_count;
		return res;
	case PE_NOT:
		return pexpr_test_eq(e1->left.pexpr, e2->left.pexpr, data);
	}

	return false;
}

/*
 * print a pexpr
 */
static void pexpr_print_util(struct pexpr *e, int prevtoken)
{
	if (!e)
		return;

	switch (e->type) {
	case PE_SYMBOL:
		printf("%s", str_get(&e->left.fexpr->name));
		break;
	case PE_AND:
		if (prevtoken != PE_AND && prevtoken != -1)
			printf("(");
		pexpr_print_util(e->left.pexpr, PE_AND);
		printf(" && ");
		pexpr_print_util(e->right.pexpr, PE_AND);
		if (prevtoken != PE_AND && prevtoken != -1)
			printf(")");
		break;
	case PE_OR:
		if (prevtoken != PE_OR && prevtoken != -1)
			printf("(");
		pexpr_print_util(e->left.pexpr, PE_OR);
		printf(" || ");
		pexpr_print_util(e->right.pexpr, PE_OR);
		if (prevtoken != PE_OR && prevtoken != -1)
			printf(")");
		break;
	case PE_NOT:
		printf("!");
		pexpr_print_util(e->left.pexpr, PE_NOT);
		break;
	}
}
void pexpr_print(char *tag, struct pexpr *e, int prevtoken)
{
	printf("%s: ", tag);
	pexpr_print_util(e, prevtoken);
	printf("\n");
}

/*
 * convert a fexpr to a pexpr
 */
struct pexpr *pexpr_alloc_symbol(struct fexpr *fe)
{
	struct pexpr *pe = xmalloc(sizeof(*pe));

	pexpr_construct_sym(pe, fe, 1);
	return pe;
}

void pexpr_construct_or(struct pexpr *e, struct pexpr *left,
			     struct pexpr *right, unsigned int ref_count)
{
	e->type = PE_OR;
	e->left.pexpr = left;
	e->right.pexpr = right;
	e->ref_count = ref_count;
}

void pexpr_construct_and(struct pexpr *e, struct pexpr *left,
			     struct pexpr *right, unsigned int ref_count)
{
	e->type = PE_AND;
	e->left.pexpr = left;
	e->right.pexpr = right;
	e->ref_count = ref_count;
}

void pexpr_construct_not(struct pexpr *e, struct pexpr *left,
			  unsigned int ref_count)
{
	e->type = PE_NOT;
	e->left.pexpr = left;
	e->right.pexpr = NULL;
	e->ref_count = ref_count;
}

void pexpr_construct_sym(struct pexpr *e, struct fexpr *left,
			  unsigned int ref_count)
{
	e->type = PE_SYMBOL;
	e->left.fexpr = left;
	e->right.pexpr = NULL;
	e->ref_count = ref_count;
}
