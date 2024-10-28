/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Patrick Franz <deltaone@debian.org>
 */

#ifndef DEFS_H
#define DEFS_H

/* global variables */
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>

#include <xalloc.h>

#include "lkc.h"
#include "expr.h"
#include "list_types.h"

extern bool CFDEBUG;
extern bool stop_rangefix;

#define printd(fmt...) do { \
	if (CFDEBUG) \
		printf(fmt); \
} while (0)

/*
 * Helper macros for use of list.h with type safety.
 * Lists of type X can then be defined as
 * `struct X_list {
 *	struct list_head list;
 * }`,
 * which contains the head of the list, and the nodes with the actual elements
 * are contained in `struct X_node {
 *	struct X *elem;
 *	struct list_head node;
 * }`
 */

/* macros for internal usage */
#define __NODE_T(prefix) struct prefix##_node
#define __LIST_T(prefix) struct prefix##_list
#define __CF_DEFS_TO_STR2(x) #x
#define __CF_DEFS_TO_STR(x) __CF_DEFS_TO_STR2(x)
#define __ASSERT_LIST_PREF(list, prefix)                                       \
	_Static_assert(__builtin_types_compatible_p(typeof(*list),             \
						    __LIST_T(prefix)),         \
		       "Incorrect type of list, should be `" __CF_DEFS_TO_STR( \
			       __LIST_T(prefix)) " *`")
#define __ASSERT_NODE_PREF(node, prefix)                                       \
	_Static_assert(__builtin_types_compatible_p(typeof(*node),             \
						    __NODE_T(prefix)),         \
		       "Incorrect type of node, should be `" __CF_DEFS_TO_STR( \
			       __LIST_T(prefix)) " *`")

/*
 * CF_ALLOC_NODE - Utility macro for allocating, initializing and returning an
 * object of a type like struct fexpr_node
 *
 * @node_type: type of the object to create a pointer to (e.g. struct fexpr_node)
 * @el: the value to set field .element to
 */
#define CF_ALLOC_NODE(el, prefix)                          \
	({                                                 \
		__NODE_T(prefix) *__node_cf_alloc =        \
			xmalloc(sizeof(*__node_cf_alloc)); \
		__node_cf_alloc->elem = el;                \
		INIT_LIST_HEAD(&__node_cf_alloc->node);    \
		__node_cf_alloc;                           \
	})

/*
 * constructs an object using CF_ALLOC_NODE(node_type, el) and then adds to the
 * end of list->list
 */
#define CF_PUSH_BACK(list_, el, prefix)                                    \
	do {                                                                  \
		__ASSERT_LIST_PREF(list_, prefix);                            \
		__NODE_T(prefix) *__cf_emplace_back_node =                    \
			CF_ALLOC_NODE(el, prefix);                            \
		list_add_tail(&__cf_emplace_back_node->node, &(list_)->list); \
	} while (0)

/*
 * frees all nodes and then list_
 */
#define CF_LIST_FREE(list_, prefix)                                      \
	do {                                                             \
		__NODE_T(prefix) * __node, *__next;                      \
		__ASSERT_LIST_PREF(list_, prefix);                       \
		list_for_each_entry_safe(__node, __next, &(list_)->list, \
					 node) {                         \
			list_del(&__node->node);                         \
			free(__node);                                    \
		}                                                        \
		free(list_);                                             \
	} while (0)

#define __CF_LIST_INIT(full_list_type)                                        \
	({                                                                    \
		full_list_type *__cf_list = xmalloc(sizeof(*__cf_list)); \
		INIT_LIST_HEAD(&__cf_list->list);                             \
		__cf_list;                                                    \
	})

#define __CF_DEF_LIST(name, full_list_type) \
	full_list_type *name = __CF_LIST_INIT(full_list_type)

/*
 * declares and initializes a list
 */
#define CF_DEF_LIST(name, prefix) __CF_DEF_LIST(name, __LIST_T(prefix))

/*
 * returns initialized a list
 */
#define CF_LIST_INIT(prefix) __CF_LIST_INIT(__LIST_T(prefix))

#define CF_LIST_FOR_EACH(node_, list_, prefix)                         \
	list_for_each_entry(node_, ({                                  \
				    __ASSERT_LIST_PREF(list_, prefix); \
				    __ASSERT_NODE_PREF(node_, prefix); \
				    &(list_)->list;                    \
			    }),                                        \
			    node)

#define CF_LIST_COPY(orig, prefix)                         \
	({                                                 \
		__CF_DEF_LIST(__ret, typeof(*orig));       \
		__NODE_T(prefix) * __node;                 \
		CF_LIST_FOR_EACH(__node, orig, prefix)     \
		CF_PUSH_BACK(__ret, __node->elem, prefix); \
		__ret;                                     \
	})

/*
 * For functions that construct nested pexpr expressions.
 */
enum pexpr_move {
	PEXPR_ARG1,	/* put reference to first pexpr */
	PEXPR_ARG2,	/* put reference to second pexpr */
	PEXPR_ARGX	/* put all references to pexpr's */
};


/* different types for f_expr */
enum fexpr_type {
	FE_SYMBOL,
	FE_NPC, /* no prompt condition */
	FE_TRUE,  /* constant of value True */
	FE_FALSE,  /* constant of value False */
	FE_NONBOOL,  /* for all non-(boolean/tristate) known values */
	FE_CHOICE, /* symbols of type choice */
	FE_SELECT, /* auxiliary variable for selected symbols */
	FE_TMPSATVAR /* temporary sat-variable (Tseytin) */
};

/* struct for a propositional logic formula */
struct fexpr {
	/* name of the feature expr */
	struct gstr name;

	/* associated symbol */
	struct symbol *sym;

	/* integer value for the SAT solver */
	int satval;

	/* assumption in the last call to PicoSAT */
	bool assumption;

	/* type of the fexpr */
	enum fexpr_type type;

	union {
		/* symbol */
		struct {
			tristate tri;
		};
		/* EQUALS */
		struct {
			struct symbol *eqsym;
			struct symbol *eqvalue;
		};
		/* HEX, INTEGER, STRING */
		struct {
			struct gstr nb_val;
		};
	};
};

/* struct definitions for lists */
struct fexpr_node {
	struct fexpr *elem;
	struct list_head node;
};

struct fexpr_list {
	struct list_head list;
};

struct fexl_list {
	struct list_head list;
};

struct fexl_node {
	struct fexpr_list *elem;
	struct list_head node;
};

struct pexpr_list {
	struct list_head list;
};

struct pexpr_node {
	struct pexpr *elem;
	struct list_head node;
};

/**
 * struct defm_list - Map from values of default properties of a symbol to their
 * (accumulated) conditions
 */
struct defm_list {
	struct list_head list;
};

struct defm_node {
	struct default_map *elem;
	struct list_head node;
};

struct sfix_list {
	struct list_head list;
};

struct sfix_node {
	struct symbol_fix *elem;
	struct list_head node;
};

struct sfl_list {
	struct list_head list;
};

struct sfl_node {
	struct sfix_list *elem;
	struct list_head node;
};

struct sym_list {
	struct list_head list;
};

struct sym_node {
	struct symbol *elem;
	struct list_head node;
};

struct prop_list {
	struct list_head list;
};

struct prop_node {
	struct property *elem;
	struct list_head node;
};

struct sdv_list {
	struct list_head list;
};

struct sdv_node {
	struct symbol_dvalue *elem;
	struct list_head node;
};


enum pexpr_type {
	PE_SYMBOL,
	PE_AND,
	PE_OR,
	PE_NOT
};

union pexpr_data {
	struct pexpr *pexpr;
	struct fexpr *fexpr;
};

/**
 * struct pexpr - a node in a tree representing a propositional formula
 * @type: Type of the node
 * @left: left-hand-side for AND and OR, the unique operand for NOT, and for
 * SYMBOL it contains the fpexpr.
 * @right: right-hand-side for AND and OR
 * @ref_count: Number of calls to pexpr_put() that need to effectuated with this
 * pexpr for it to get free'd.
 *
 * Functions that return new struct pexpr instances (like pexpr_or(),
 * pexpr_or_share(), pexf(), ...) set @ref_count in a way that accounts for the
 * new reference that they return (e.g. pexf() will always set it to 1).
 * Functions with arguments of type ``struct pexpr *`` will generally keep the
 * reference intact, so that for example
 * ``e = pexf(sym); not_e = pexpr_not_share(e)`` would require
 * ``pexpr_put(not_e)`` before not_e can be free'd and additionally
 * ``pexpr_put(e)`` for e to get free'd. Some functions take an argument of type
 * ``enum pexpr_move`` which function as a wrapper of sorts that first executes
 * a function and then pexpr_put's the argument(s) specified by the
 * ``enum pexpr_move`` argument (e.g. the normal function for OR is
 * pexpr_or_share() and the wrapper is pexpr_or()).
 */
struct pexpr {
	enum pexpr_type type;
	union pexpr_data left, right;
	unsigned int ref_count;
};

enum symboldv_type {
	SDV_BOOLEAN,	/* boolean/tristate */
	SDV_NONBOOLEAN	/* string/int/hex */
};

/**
 * struct default_map - Map entry from default values to their condition
 * @val: value of the default property. Not 'owned' by this struct and
 * therefore shouldn't be free'd.
 * @e: condition that implies that the symbol assumes the @val. Needs to be
 * pexpr_put when free'ing.
 */
struct default_map {
	struct fexpr *val;
	struct pexpr *e;
};

struct symbol_dvalue {
	struct symbol *sym;

	enum symboldv_type type;

	union {
		/* boolean/tristate */
		tristate tri;

		/* string/int/hex */
		struct gstr nb_val;
	};
};

enum symbolfix_type {
	SF_BOOLEAN,	/* boolean/tristate */
	SF_NONBOOLEAN,	/* string/int/hex */
	SF_DISALLOWED	/* disallowed non-boolean values */
};

struct symbol_fix {
	struct symbol *sym;

	enum symbolfix_type type;

	union {
		/* boolean/tristate */
		tristate tri;

		/* string/int/hex */
		struct gstr nb_val;

		/* disallowed non-boolean values */
		struct gstr disallowed;
	};
};

struct constants {
	struct fexpr *const_false;
	struct fexpr *const_true;
	struct fexpr *symbol_yes_fexpr;
	struct fexpr *symbol_mod_fexpr;
	struct fexpr *symbol_no_fexpr;
};

struct cfdata {
	unsigned int sat_variable_nr;
	unsigned int tmp_variable_nr;
	struct fexpr **satmap; // map SAT variables to fexpr
	size_t satmap_size;
	struct constants *constants;
	struct sdv_list *sdv_symbols; // array with conflict-symbols
};

#endif
