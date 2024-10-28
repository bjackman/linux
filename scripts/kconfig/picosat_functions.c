// SPDX-License-Identifier: GPL-2.0

#include <dlfcn.h>
#include <unistd.h>

#include "array_size.h"

#include "cf_defs.h"
#include "picosat_functions.h"

const char *picosat_lib_names[] = { "libpicosat-trace.so",
				    "libpicosat-trace.so.0",
				    "libpicosat-trace.so.1" };

PicoSAT *(*picosat_init)(void);
int (*picosat_add)(PicoSAT *pico, int lit);
int (*picosat_deref)(PicoSAT *pico, int lit);
void (*picosat_assume)(PicoSAT *pico, int lit);
int (*picosat_sat)(PicoSAT *pico, int decision_limit);
const int *(*picosat_failed_assumptions)(PicoSAT *pico);
int (*picosat_added_original_clauses)(PicoSAT *pico);
int (*picosat_enable_trace_generation)(PicoSAT *pico);
void (*picosat_print)(PicoSAT *pico, FILE *file);

#define PICOSAT_FUNCTION_LIST             \
	X(picosat_init)                   \
	X(picosat_add)                    \
	X(picosat_deref)                  \
	X(picosat_assume)                 \
	X(picosat_sat)                    \
	X(picosat_failed_assumptions)     \
	X(picosat_added_original_clauses) \
	X(picosat_enable_trace_generation)\
	X(picosat_print)

static void load_function(const char *name, void **ptr, void *handle, bool *failed)
{
	if (*failed)
		return;

	*ptr = dlsym(handle, name);
	if (!*ptr) {
		printd("While loading %s: %s\n", name, dlerror());
		*failed = true;
	}
}

bool load_picosat(void)
{
	void *handle = NULL;
	bool failed = false;

	/*
	 * Try different names for the .so library. This is necessary since
	 * all packages don't use the same versioning.
	 */
	for (int i = 0; i < ARRAY_SIZE(picosat_lib_names) && !handle; ++i)
		handle = dlopen(picosat_lib_names[i], RTLD_LAZY);
	if (!handle) {
		printd("%s\n", dlerror());
		return false;
	}

#define X(name) load_function(#name, (void **) &name, handle, &failed);

	PICOSAT_FUNCTION_LIST
#undef X

	if (failed) {
		dlclose(handle);
		return false;
	} else
		return true;
}
