/*-------------------------------------------------------------------------
 *
 * pg_database.c
 *	  routines to support manipulation of the pg_database relation
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/catalog/pg_database.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/indexing.h"
#include "catalog/pg_database.h"
#include "utils/fmgroids.h"

void
UnsetDatabaseChecksumsFlag(void)
{
	Relation		pgdbrel;
	HeapTuple		tup;
	ScanKeyData		scankey;
	SysScanDesc		scan;

	pgdbrel = table_open(DatabaseRelationId, RowExclusiveLock);

	ScanKeyInit(&scankey,
				Anum_pg_database_dathaschecksums,
				BTEqualStrategyNumber, F_BOOLEQ,
				BoolGetDatum(true));

	scan = systable_beginscan(pgdbrel, InvalidOid, false,
							  NULL, 1, &scankey);

	while (HeapTupleIsValid((tup = systable_getnext(scan))))
	{
		Form_pg_database	pgdb_tup = (Form_pg_database) GETSTRUCT(tup);

		pgdb_tup->dathaschecksums = false;

		CatalogTupleUpdate(pgdbrel, &tup->t_self, tup);
	}
	
	systable_endscan(scan);

	table_close(pgdbrel, RowExclusiveLock);
}
