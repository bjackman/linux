/* SPDX-License-Identifier: GPL-2.0 */

#ifndef PICOSAT_FUNCTIONS_H
#define PICOSAT_FUNCTIONS_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PICOSAT_UNKNOWN         0
#define PICOSAT_SATISFIABLE     10
#define PICOSAT_UNSATISFIABLE   20

typedef struct PicoSAT PicoSAT;

extern PicoSAT *(*picosat_init)(void);
extern int (*picosat_add)(PicoSAT *pico, int lit);
extern int (*picosat_deref)(PicoSAT *pico, int lit);
extern void (*picosat_assume)(PicoSAT *pico, int lit);
extern int (*picosat_sat)(PicoSAT *pico, int decision_limit);
extern const int *(*picosat_failed_assumptions)(PicoSAT *pico);
extern int (*picosat_added_original_clauses)(PicoSAT *pico);
extern int (*picosat_enable_trace_generation)(PicoSAT *pico);
extern void (*picosat_print)(PicoSAT *pico, FILE *file);

bool load_picosat(void);

#ifdef __cplusplus
}
#endif

#endif // PICOSAT_FUNCTIONS_H
