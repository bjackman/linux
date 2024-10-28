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

#include "configfix.h"
#include "internal.h"
#include "picosat_functions.h"
#include "cf_utils.h"
#include "cf_constraints.h"
#include "cf_rangefix.h"
#include "cf_defs.h"
#include "expr.h"
#include "list.h"
#include "lkc.h"

bool CFDEBUG;
bool stop_rangefix;

static PicoSAT *pico;
static bool init_done;
static struct sym_list *conflict_syms;

static bool sdv_within_range(struct sdv_list *symbols);

/* -------------------------------------- */

struct sfix_list **run_satconf(struct symbol_dvalue **symbols, size_t n,
			       size_t *num_solutions)
{
	CF_DEF_LIST(symbols_list, sdv);
	struct sfl_list *solutions;
	struct sfix_list **solutions_arr;
	struct sfl_node *node;
	size_t i;

	i = 0;
	for (i = 0; i < n; ++i)
		CF_PUSH_BACK(symbols_list, symbols[i], sdv);

	solutions = run_satconf_list(symbols_list);
	*num_solutions = list_size(&solutions->list);
	solutions_arr = xcalloc(*num_solutions, sizeof(struct sfix_list *));
	i = 0;
	CF_LIST_FOR_EACH(node, solutions, sfl)
		solutions_arr[i++] = node->elem;
	CF_LIST_FREE(solutions, sfl);
	return solutions_arr;
}

struct sfl_list *run_satconf_list(struct sdv_list *symbols)
{
	clock_t start, end;
	double time;
	struct symbol *sym;
	struct sdv_node *node;
	int res;
	struct sfl_list *ret;

	static struct constants constants = {NULL, NULL, NULL, NULL, NULL};
	static struct cfdata data = {
		1,    // unsigned int sat_variable_nr
		1,    // unsigned int tmp_variable_nr
		NULL, // struct fexpr *satmap
		0,    // size_t satmap_size
		&constants, // struct constants *constants
		NULL // array with conflict-symbols
	};


	/* check whether all values can be applied -> no need to run */
	if (sdv_within_range(symbols)) {
		printd("\nAll symbols are already within range.\n\n");
		return CF_LIST_INIT(sfl);
	}

	if (!init_done) {
		printd("\n");
		printd("Init...");

		/* measure time for constructing constraints and clauses */
		start = clock();

		/* initialize satmap and cnf_clauses */
		init_data(&data);

		/* creating constants */
		create_constants(&data);

		/* assign SAT variables & create sat_map */
		create_sat_variables(&data);

		/* get the constraints */
		build_constraints(&data);

		end = clock();
		time = ((double)(end - start)) / CLOCKS_PER_SEC;

		printd("done. (%.6f secs.)\n", time);

		/* start PicoSAT */
		pico = initialize_picosat();
		printd("Building CNF-clauses...");
		start = clock();

		/* construct the CNF clauses */
		construct_cnf_clauses(pico, &data);

		end = clock();
		time = ((double)(end - start)) / CLOCKS_PER_SEC;

		printd("done. (%.6f secs.)\n", time);

		printd("CNF-clauses added: %d\n",
		       picosat_added_original_clauses(pico));

		init_done = true;
	}

	/* copy array with symbols to change */
	data.sdv_symbols = CF_LIST_COPY(symbols, sdv);

	/* add assumptions for conflict-symbols */
	sym_add_assumption_sdv(pico, data.sdv_symbols);

	/* add assumptions for all other symbols */
	for_all_symbols(sym) {
		if (sym->type == S_UNKNOWN)
			continue;

		if (!sym_is_sdv(data.sdv_symbols, sym))
			sym_add_assumption(pico, sym);
	}

	/* store the conflict symbols */
	conflict_syms = CF_LIST_INIT(sym);
	CF_LIST_FOR_EACH(node, data.sdv_symbols, sdv)
		CF_PUSH_BACK(conflict_syms, node->elem->sym, sym);

	printd("Solving SAT-problem...");
	start = clock();

	res = picosat_sat(pico, -1);

	end = clock();
	time = ((double)(end - start)) / CLOCKS_PER_SEC;
	printd("done. (%.6f secs.)\n\n", time);

	if (res == PICOSAT_SATISFIABLE) {
		printd("===> PROBLEM IS SATISFIABLE <===\n");

		ret = CF_LIST_INIT(sfl);

	} else if (res == PICOSAT_UNSATISFIABLE) {
		printd("===> PROBLEM IS UNSATISFIABLE <===\n");
		printd("\n");

		ret = rangefix_run(pico, &data);
	} else {
		printd("Unknown if satisfiable.\n");

		ret = CF_LIST_INIT(sfl);
	}

	CF_LIST_FREE(data.sdv_symbols, sdv);
	return ret;
}

/*
 * check whether a symbol is a conflict symbol
 */
static bool sym_is_conflict_sym(struct symbol *sym)
{
	struct sym_node *node;

	CF_LIST_FOR_EACH(node, conflict_syms, sym)
		if (sym == node->elem)
			return true;

	return false;
}

/*
 * check whether all conflict symbols are set to their target values
 */
static bool syms_have_target_value(struct sfix_list *list)
{
	struct symbol_fix *fix;
	struct sfix_node *node;

	CF_LIST_FOR_EACH(node, list, sfix) {
		fix = node->elem;

		if (!sym_is_conflict_sym(fix->sym))
			continue;

		sym_calc_value(fix->sym);

		if (sym_is_boolean(fix->sym)) {
			if (fix->tri != sym_get_tristate_value(fix->sym))
				return false;
		} else {
			if (strcmp(str_get(&fix->nb_val),
				   sym_get_string_value(fix->sym)) != 0)
				return false;
		}
	}

	return true;
}

/*
 *
 * apply the fixes from a diagnosis
 */
int apply_fix(struct sfix_list *fix)
{
	struct symbol_fix *sfix;
	struct sfix_node *node, *next;
	unsigned int no_symbols_set = 0, iterations = 0, manually_changed = 0;
	size_t fix_size = list_size(&fix->list);
	struct sfix_list *tmp = CF_LIST_COPY(fix, sfix);

	printd("Trying to apply fixes now...\n");

	while (no_symbols_set < fix_size && !syms_have_target_value(fix)) {
		if (iterations > fix_size * 2) {
			printd("\nCould not apply all values :-(.\n");
			return manually_changed;
		}

		list_for_each_entry_safe(node, next, &tmp->list, node) {
			sfix = node->elem;

			/* update symbol's current value */
			sym_calc_value(sfix->sym);

			/* value already set? */
			if (sfix->type == SF_BOOLEAN) {
				if (sfix->tri ==
				    sym_get_tristate_value(sfix->sym)) {
					list_del(&node->node);
					no_symbols_set++;
					continue;
				}
			} else if (sfix->type == SF_NONBOOLEAN) {
				if (strcmp(str_get(&sfix->nb_val),
					   sym_get_string_value(sfix->sym)) ==
				    0) {
					list_del(&node->node);
					no_symbols_set++;
					continue;
				}
			} else {
				perror("Error applying fix. Value set for disallowed.");
			}

			/* could not set value, try next */
			if (sfix->type == SF_BOOLEAN) {
				if (!sym_set_tristate_value(sfix->sym,
							    sfix->tri))
					continue;
			} else if (sfix->type == SF_NONBOOLEAN) {
				if (!sym_set_string_value(
					    sfix->sym,
					    str_get(&sfix->nb_val)))
					continue;
			} else {
				perror("Error applying fix. Value set for disallowed.");
			}

			/* could set value, remove from tmp */
			manually_changed++;
			if (sfix->type == SF_BOOLEAN) {
				printd("%s set to %s.\n",
				       sym_get_name(sfix->sym),
				       tristate_get_char(sfix->tri));
			} else if (sfix->type == SF_NONBOOLEAN) {
				printd("%s set to %s.\n",
				       sym_get_name(sfix->sym),
				       str_get(&sfix->nb_val));
			}

			list_del(&node->node);
			no_symbols_set++;
		}

		iterations++;
	}

	printd("Fixes successfully applied.\n");

	return manually_changed;
}

/*
 * stop RangeFix after the next iteration
 */
void interrupt_rangefix(void)
{
	stop_rangefix = true;
}

/*
 * check whether all symbols are already within range
 */
static bool sdv_within_range(struct sdv_list *symbols)
{
	struct symbol_dvalue *sdv;
	struct sdv_node *node;

	CF_LIST_FOR_EACH(node, symbols, sdv) {
		sdv = node->elem;

		assert(sym_is_boolean(sdv->sym));

		if (sdv->tri == sym_get_tristate_value(sdv->sym))
			continue;

		if (!sym_tristate_within_range(sdv->sym, sdv->tri))
			return false;
	}

	return true;
}

/*
 * for use in .cc files
 */
struct sfix_list *select_solution(struct sfl_list *solutions, int index)
{
	return list_at_index(index, &solutions->list, struct sfl_node, node)
		->elem;
}

struct symbol_fix *select_symbol(struct sfix_list *solution, int index)
{
	return list_at_index(index, &solution->list, struct sfix_node, node)
		->elem;
}
