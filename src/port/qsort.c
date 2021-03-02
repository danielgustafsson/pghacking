/*
 *	qsort.c: standard quicksort algorithm
 */

#include "c.h"

#define ST_SORT pg_qsort
#define ST_ELEMENT_TYPE_VOID
#define ST_COMPARE_RUNTIME_POINTER
#define ST_SCOPE
#define ST_DECLARE
#define ST_DEFINE
#include "lib/sort_template.h"

#define ST_SORT qsort_strcmp
#define ST_ELEMENT_TYPE_VOID
#define ST_COMPARE(a, b) \
	strcmp(*(const char *const *) (a), *(const char *const *) (b))
#define ST_SCOPE extern
#define ST_DECLARE
#define ST_DEFINE
#include "lib/sort_template.h"


