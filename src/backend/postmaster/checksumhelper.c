/*-------------------------------------------------------------------------
 *
 * checksumhelper.c
 *	  Background worker to walk the database and write checksums to pages
 *
 * When enabling data checksums on a database at initdb time or with
 * pg_checksums, no extra process is required as each page is checksummed, and
 * verified, at accesses.  When enabling checksums on an already running
 * cluster, which was not initialized with checksums, this helper worker will
 * ensure that all pages are checksummed before verification of the checksums
 * is turned on.
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/postmaster/checksumhelper.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_class.h"
#include "catalog/pg_database.h"
#include "commands/vacuum.h"
#include "common/relpath.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "postmaster/bgwriter.h"
#include "postmaster/checksumhelper.h"
#include "storage/bufmgr.h"
#include "storage/checksum.h"
#include "storage/lmgr.h"
#include "storage/ipc.h"
#include "storage/procarray.h"
#include "storage/smgr.h"
#include "tcop/tcopprot.h"
#include "utils/fmgroids.h"
#include "utils/lsyscache.h"
#include "utils/ps_status.h"

#define CHECKSUMHELPER_MAX_DB_RETRIES 5

typedef enum
{
	CHECKSUMHELPER_SUCCESSFUL = 0,
	CHECKSUMHELPER_ABORTED,
	CHECKSUMHELPER_FAILED,
	CHECKSUMHELPER_RETRYDB,
}			ChecksumHelperResult;

typedef struct ChecksumHelperShmemStruct
{
	/*
	 * Access to launcher_started and abort must be protected by
	 * ChecksumHelperLock.
	 */
	bool		launcher_started;
	bool		abort;

	/*
	 * Access to other members can be done without a lock, as while they are
	 * in shared memory, they are never concurrently accessed. When a worker
	 * is running, the launcher is only waiting for that worker to finish.
	 */
	ChecksumHelperResult success;
	bool		process_shared_catalogs;
	/* Parameter values set on start */
	int			cost_delay;
	int			cost_limit;
}			ChecksumHelperShmemStruct;

/* Shared memory segment for checksumhelper */
static ChecksumHelperShmemStruct * ChecksumHelperShmem;

/* Bookkeeping for work to do */
typedef struct ChecksumHelperDatabase
{
	Oid			dboid;
	char	   *dbname;
}			ChecksumHelperDatabase;

typedef struct ChecksumHelperRelation
{
	Oid			reloid;
	char		relkind;
}			ChecksumHelperRelation;

typedef struct ChecksumHelperResultEntry
{
	Oid						dboid;
	ChecksumHelperResult	result;
	int						retries;
}			ChecksumHelperResultEntry;


/* Prototypes */
static List *BuildDatabaseList(void);
static List *BuildRelationList(bool include_shared);
static List *BuildTempTableList(void);
static ChecksumHelperResult ProcessDatabase(ChecksumHelperDatabase * db);
static void launcher_cancel_handler(SIGNAL_ARGS);

static void SetDatabaseChecksumFlag(Oid dboid);

/*
 * Main entry point for checksumhelper launcher process.
 */
void
StartChecksumHelperLauncher(int cost_delay, int cost_limit)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;

	LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
	if (ChecksumHelperShmem->abort)
	{
		LWLockRelease(ChecksumHelperLock);
		ereport(ERROR,
				(errmsg("checksum enabling has been aborted")));
	}

	if (ChecksumHelperShmem->launcher_started)
	{
		/* Failed to set means somebody else started */
		LWLockRelease(ChecksumHelperLock);
		ereport(NOTICE,
				(errmsg("checksums are already being enabled")));
		return;
	}

	ChecksumHelperShmem->cost_delay = cost_delay;
	ChecksumHelperShmem->cost_limit = cost_limit;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperLauncherMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksumhelper launcher");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksumhelper launcher");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = (Datum) 0;

	ChecksumHelperShmem->launcher_started = true;
	LWLockRelease(ChecksumHelperLock);

	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
	{
		LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
		ChecksumHelperShmem->launcher_started = false;
		LWLockRelease(ChecksumHelperLock);
		ereport(ERROR,
				(errmsg("failed to start background worker to enable checksums")));
	}
}

/*
 * ShutdownChecksumHelperIfRunning
 *		Request shutdown of the checksumhelper
 *
 * This does not turn off processing immediately, it signals the checksum
 * process to end when done with the current block.
 */
void
ShutdownChecksumHelperIfRunning(void)
{
	/* If the launcher isn't started, there is nothing to shut down */
	LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
	if (ChecksumHelperShmem->launcher_started)
		ChecksumHelperShmem->abort = true;
	LWLockRelease(ChecksumHelperLock);
}

/*
 * ProcessSingleRelationFork
 *		Enable checksums in a single relation/fork.
 *
 * Returns true if successful, and false if *aborted*. On error, an actual
 * error is raised in the lower levels.
 */
static bool
ProcessSingleRelationFork(Relation reln, ForkNumber forkNum, BufferAccessStrategy strategy)
{
	BlockNumber numblocks = RelationGetNumberOfBlocksInFork(reln, forkNum);
	BlockNumber b;
	char		activity[NAMEDATALEN * 2 + 128];

	for (b = 0; b < numblocks; b++)
	{
		Buffer		buf = ReadBufferExtended(reln, forkNum, b, RBM_NORMAL, strategy);

		/*
		 * Report to pgstat every 100 blocks (so as not to "spam")
		 */
		if ((b % 100) == 0)
		{
			snprintf(activity, sizeof(activity) - 1, "processing: %s.%s (%s block %d/%d)",
					 get_namespace_name(RelationGetNamespace(reln)), RelationGetRelationName(reln),
					 forkNames[forkNum], b, numblocks);
			pgstat_report_activity(STATE_RUNNING, activity);
		}

		/* Need to get an exclusive lock before we can flag as dirty */
		LockBuffer(buf, BUFFER_LOCK_EXCLUSIVE);

		/*
		 * Mark the buffer as dirty and force a full page write.  We have to
		 * re-write the page to WAL even if the checksum hasn't changed,
		 * because if there is a replica it might have a slightly different
		 * version of the page with an invalid checksum, caused by unlogged
		 * changes (e.g. hintbits) on the master happening while checksums
		 * were off. This can happen if there was a valid checksum on the page
		 * at one point in the past, so only when checksums are first on, then
		 * off, and then turned on again.
		 */
		START_CRIT_SECTION();
		MarkBufferDirty(buf);
		log_newpage_buffer(buf, false);
		END_CRIT_SECTION();

		UnlockReleaseBuffer(buf);

		/*
		 * This is the only place where we check if we are asked to abort, the
		 * abortion will bubble up from here. It's safe to check this without
		 * a lock, because if we miss it being set, we will try again soon.
		 */
		if (ChecksumHelperShmem->abort)
			return false;

		vacuum_delay_point();
	}

	return true;
}

/*
 * ProcessSingleRelationByOid
 *		Process a single relation based on oid.
 *
 * Returns true if successful, and false if *aborted*. On error, an actual error
 * is raised in the lower levels.
 */
static bool
ProcessSingleRelationByOid(Oid relationId, BufferAccessStrategy strategy)
{
	Relation	rel;
	ForkNumber	fnum;
	bool		aborted = false;

	StartTransactionCommand();

	elog(DEBUG2, "background worker \"checksumhelper\" starting to process relation %u", relationId);
	rel = try_relation_open(relationId, AccessShareLock);
	if (rel == NULL)
	{
		/*
		 * Relation no longer exist. We consider this a success, since there
		 * are no pages in it that need checksums, and thus return true.
		 */
		elog(DEBUG1, "background worker \"checksumhelper\" skipping relation %u as it no longer exists", relationId);
		CommitTransactionCommand();
		pgstat_report_activity(STATE_IDLE, NULL);
		return true;
	}
	RelationOpenSmgr(rel);

	for (fnum = 0; fnum <= MAX_FORKNUM; fnum++)
	{
		if (smgrexists(rel->rd_smgr, fnum))
		{
			if (!ProcessSingleRelationFork(rel, fnum, strategy))
			{
				aborted = true;
				break;
			}
		}
	}
	relation_close(rel, AccessShareLock);
	elog(DEBUG2, "background worker \"checksumhelper\" done with relation %u: %s",
		 relationId, (aborted ? "aborted" : "finished"));

	CommitTransactionCommand();

	pgstat_report_activity(STATE_IDLE, NULL);

	return !aborted;
}

/*
 * ProcessDatabase
 *		Enable checksums in a single database.
 *
 * We do this by launching a dynamic background worker into this database, and
 * waiting for it to finish.  We have to do this in a separate worker, since
 * each process can only be connected to one database during its lifetime.
 */
static ChecksumHelperResult
ProcessDatabase(ChecksumHelperDatabase * db)
{
	BackgroundWorker bgw;
	BackgroundWorkerHandle *bgw_handle;
	BgwHandleStatus status;
	pid_t		pid;
	char		activity[NAMEDATALEN + 64];

	ChecksumHelperShmem->success = CHECKSUMHELPER_FAILED;

	memset(&bgw, 0, sizeof(bgw));
	bgw.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	bgw.bgw_start_time = BgWorkerStart_RecoveryFinished;
	snprintf(bgw.bgw_library_name, BGW_MAXLEN, "postgres");
	snprintf(bgw.bgw_function_name, BGW_MAXLEN, "ChecksumHelperWorkerMain");
	snprintf(bgw.bgw_name, BGW_MAXLEN, "checksumhelper worker");
	snprintf(bgw.bgw_type, BGW_MAXLEN, "checksumhelper worker");
	bgw.bgw_restart_time = BGW_NEVER_RESTART;
	bgw.bgw_notify_pid = MyProcPid;
	bgw.bgw_main_arg = ObjectIdGetDatum(db->dboid);

	/*
	 * If there are no worker slots available, make sure we retry processing
	 * this database. This will make the checksumhelper move on to the next
	 * database and quite likely fail with the same problem. Maybe we need a
	 * backoff to avoid running through all the databases here in short order.
	 */
	if (!RegisterDynamicBackgroundWorker(&bgw, &bgw_handle))
	{
		ereport(WARNING,
				(errmsg("failed to start worker for enabling checksums in \"%s\", retrying",
						db->dbname),
				 errhint("The max_worker_processes setting might be too low.")));
		return CHECKSUMHELPER_RETRYDB;
	}

	status = WaitForBackgroundWorkerStartup(bgw_handle, &pid);
	if (status == BGWH_STOPPED)
	{
		ereport(WARNING,
				(errmsg("could not start background worker for enabling checksums in \"%s\"",
						db->dbname),
				 errhint("More details on the error might be found in the server log.")));
		return CHECKSUMHELPER_FAILED;
	}

	/*
	 * If the postmaster crashed we cannot end up with checksums enabled
	 * clusterwide so we have no alternative other than exiting.
	 */
	if (status == BGWH_POSTMASTER_DIED)
		ereport(FATAL,
				(errmsg("cannot enable checksums without the postmaster process"),
				 errhint("Restart the database and restart the checksumming process by calling pg_enable_data_checksums().")));

	Assert(status == BGWH_STARTED);
	ereport(DEBUG1,
			(errmsg("started background worker \"checksumhelper\" in database \"%s\"",
					db->dbname)));

	snprintf(activity, sizeof(activity) - 1,
			 "Waiting for worker in database %s (pid %d)", db->dbname, pid);
	pgstat_report_activity(STATE_RUNNING, activity);

	status = WaitForBackgroundWorkerShutdown(bgw_handle);
	if (status == BGWH_POSTMASTER_DIED)
		ereport(FATAL,
				(errmsg("postmaster exited during checksum processing in \"%s\"",
						db->dbname),
				 errhint("Restart the database and restart the checksumming process by calling pg_enable_data_checksums().")));

	if (ChecksumHelperShmem->success == CHECKSUMHELPER_ABORTED)
		ereport(LOG,
				(errmsg("background worker for enabling checksums was aborted during processing in \"%s\"",
						db->dbname)));

	ereport(DEBUG1,
			(errmsg("background worker \"checksumhelper\" in \"%s\" completed",
					db->dbname)));

	pgstat_report_activity(STATE_IDLE, NULL);

	return ChecksumHelperShmem->success;
}

static void
SetDatabaseChecksumFlag(Oid dboid)
{
	Relation	pgdbrel;
	HeapTuple	oldtuple;
	ScanKeyData	scankey;
	SysScanDesc	sysscan;

	StartTransactionCommand();

	pgdbrel = table_open(DatabaseRelationId, RowExclusiveLock);

	ScanKeyInit(&scankey,
				Anum_pg_database_oid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(dboid));
	sysscan = systable_beginscan(pgdbrel, DatabaseOidIndexId, true, NULL,
								 1, &scankey);
	oldtuple = systable_getnext(sysscan);

	/* This can't happen, or at least it shouldn't be possible to.. */
	if (!HeapTupleIsValid(oldtuple))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_DATABASE),
				 errmsg("database \"%u\" no longer exists", dboid)));

	memset(newvalue, 0, sizeof(newvalue));
	memset(newvalue_nulls, false, sizeof(newvalue_nulls));
	memset(newvalue_repl, false, sizeof(newvalue_repl));

	newvalue_repl[Anum_pg_database_dathaschecksums - 1] = true;
	if (ChecksumHelperShmem->success == CHECKSUMHELPER_SUCCESSFUL)
		newvalue[Anum_pg_database_dathaschecksums - 1] = BoolGetDatum(true);
	else
		newvalue[Anum_pg_database_dathaschecksums - 1] = BoolGetDatum(false);

	newtuple = heap_modify_tuple(oldtuple, RelationGetDescr(pgdbrel), newvalue,
								 newvalue_nulls, newvalue_repl);
	CatalogTupleUpdate(pgdbrel, &oldtuple->t_self, newtuple);

	systable_endscan(sysscan);

	table_close(pgdbrel, NoLock);

	CommitTransactionCommand();
}

static void
launcher_exit(int code, Datum arg)
{
	LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
	ChecksumHelperShmem->abort = false;
	ChecksumHelperShmem->launcher_started = false;
	LWLockRelease(ChecksumHelperLock);
}

static void
launcher_cancel_handler(SIGNAL_ARGS)
{
	LWLockAcquire(ChecksumHelperLock, LW_EXCLUSIVE);
	ChecksumHelperShmem->abort = true;
	LWLockRelease(ChecksumHelperLock);
}

static void
WaitForAllTransactionsToFinish(void)
{
	TransactionId waitforxid;

	LWLockAcquire(XidGenLock, LW_SHARED);
	waitforxid = XidFromFullTransactionId(ShmemVariableCache->nextFullXid);
	LWLockRelease(XidGenLock);

	while (true)
	{
		TransactionId oldestxid = GetOldestActiveTransactionId();

		if (TransactionIdPrecedes(oldestxid, waitforxid))
		{
			char		activity[64];

			/* Oldest running xid is older than us, so wait */
			snprintf(activity, sizeof(activity), "Waiting for current transactions to finish (waiting for %u)", waitforxid);
			pgstat_report_activity(STATE_RUNNING, activity);

			/* Retry every 5 seconds */
			ResetLatch(MyLatch);
			(void) WaitLatch(MyLatch,
							 WL_LATCH_SET | WL_TIMEOUT,
							 5000,
							 WAIT_EVENT_CHECKSUM_ENABLE_STARTCONDITION);
		}
		else
		{
			pgstat_report_activity(STATE_IDLE, NULL);
			return;
		}
	}
}

void
ChecksumHelperLauncherMain(Datum arg)
{
	List	   *DatabaseList;
	HTAB	   *ProcessedDatabases = NULL;
	ListCell   *lc;
	HASHCTL		hash_ctl;
	bool		found_failed = false;

	on_shmem_exit(launcher_exit, 0);

	ereport(DEBUG1,
			(errmsg("background worker \"checksumhelper\" launcher started")));

	pqsignal(SIGTERM, die);
	pqsignal(SIGINT, launcher_cancel_handler);

	BackgroundWorkerUnblockSignals();

	MyBackendType = B_CHECKSUMHELPER_LAUNCHER;
	init_ps_display(NULL);

	/* Initialize a hash tracking all processed databases */
	memset(&hash_ctl, 0, sizeof(hash_ctl));
	hash_ctl.keysize = sizeof(Oid);
	hash_ctl.entrysize = sizeof(ChecksumHelperResultEntry);
	ProcessedDatabases = hash_create("Processed databases",
									 64,
									 &hash_ctl,
									 HASH_ELEM | HASH_BLOBS);

	/*
	 * Initialize a connection to shared catalogs only.
	 */
	BackgroundWorkerInitializeConnection(NULL, NULL, 0);

	/*
	 * Set up so first run processes shared catalogs, but not once in every
	 * db.
	 */
	ChecksumHelperShmem->process_shared_catalogs = true;
	SyncLocal();

	while (true)
	{
		int			processed_databases = 0;

		/*
		 * Get a list of all databases to process. This may include databases
		 * that were created during our runtime.
		 *
		 * Since a database can be created as a copy of any other database
		 * (which may not have existed in our last run), we have to repeat
		 * this loop until no new databases show up in the list. Since we wait
		 * for all pre-existing transactions finish, this way we can be
		 * certain that there are no databases left without checksums.
		 */
		DatabaseList = BuildDatabaseList();

		foreach(lc, DatabaseList)
		{
			ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
			ChecksumHelperResult result;
			ChecksumHelperResultEntry *entry;
			bool			found;

			elog(DEBUG1, "Starting processing of database %s with oid %u", db->dbname, db->dboid);

			entry = (ChecksumHelperResultEntry *) hash_search(ProcessedDatabases, &db->dboid,
								HASH_FIND, NULL);

			/* Skip if this database has been processed already */
			if (entry)
			{
				if (entry->result == CHECKSUMHELPER_RETRYDB)
				{
					/*
					 * Limit the number of retries to avoid infinite looping
					 * in case there simply wont be enough workers in the
					 * cluster to finish this operation.
					 */
					if (entry->retries > CHECKSUMHELPER_MAX_DB_RETRIES)
						entry->result = CHECKSUMHELPER_FAILED;
				}

				if (entry->result != CHECKSUMHELPER_RETRYDB)
				{
					pfree(db->dbname);
					pfree(db);
					continue;
				}
			}

			result = ProcessDatabase(db);
			processed_databases++;

			if (result == CHECKSUMHELPER_SUCCESSFUL)
			{
				/*
				 * If one database has completed shared catalogs, we don't
				 * have to process them again.
				 */
				if (ChecksumHelperShmem->process_shared_catalogs)
					ChecksumHelperShmem->process_shared_catalogs = false;
			}
			else if (result == CHECKSUMHELPER_ABORTED)
				/* Abort flag set, so exit the whole process */
				return;

			entry = hash_search(ProcessedDatabases, &db->dboid, HASH_ENTER, &found);
			entry->dboid = db->dboid;
			entry->result = result;
			if (!found)
				entry->retries = 0;
			else
				entry->retries++;

			pfree(db->dbname);
			pfree(db);
		}

		elog(DEBUG1,
			 "completed one pass over all databases for checksum enabling, %i databases processed",
			 processed_databases);

		list_free(DatabaseList);

		/*
		 * If no databases were processed in this run of the loop, we have now
		 * finished all databases and no concurrently created ones can exist.
		 */
		if (processed_databases == 0)
			break;
	}

	/*
	 * ProcessedDatabases now has all databases and the results of their
	 * processing. Failure to enable checksums for a database can be because
	 * they actually failed for some reason, or because the database was
	 * dropped between us getting the database list and trying to process it.
	 * Get a fresh list of databases to detect the second case where the
	 * database was dropped before we had started processing it. If a database
	 * still exists, but enabling checksums failed then we fail the entire
	 * checksumming process and exit with an error.
	 */
	DatabaseList = BuildDatabaseList();

	foreach(lc, DatabaseList)
	{
		ChecksumHelperDatabase *db = (ChecksumHelperDatabase *) lfirst(lc);
		ChecksumHelperResult *entry;
		bool		found;

		entry = hash_search(ProcessedDatabases, (void *) &db->dboid,
							HASH_FIND, &found);

		/*
		 * We are only interested in the databases where the failed database
		 * still exist.
		 */
		if (found && *entry == CHECKSUMHELPER_FAILED)
		{
			ereport(WARNING,
					(errmsg("failed to enable checksums in \"%s\"",
							db->dbname)));
			found_failed = found;
			continue;
		}
	}

	if (found_failed)
	{
		/* Disable checksums on cluster, because we failed */
		SetDataChecksumsOff();
		ereport(ERROR,
				(errmsg("checksums failed to get enabled in all databases, aborting"),
				 errhint("The server log might have more information on the error.")));
	}

	/*
	 * Force a checkpoint to get everything out to disk. XXX: this should
	 * probably not be an IMMEDIATE checkpoint, but leave it there for now for
	 * testing.
	 */
	RequestCheckpoint(CHECKPOINT_FORCE | CHECKPOINT_WAIT | CHECKPOINT_IMMEDIATE);

	/*
	 * Everything has been processed, so flag checksums enabled.
	 */
	SetDataChecksumsOn();

	ereport(LOG,
			(errmsg("checksums enabled clusterwide")));
}

/*
 * ChecksumHelperShmemSize
 *		Compute required space for checksumhelper-related shared memory
 */
Size
ChecksumHelperShmemSize(void)
{
	Size		size;

	size = sizeof(ChecksumHelperShmemStruct);
	size = MAXALIGN(size);

	return size;
}

/*
 * ChecksumHelperShmemInit
 *		Allocate and initialize checksumhelper-related shared memory
 */
void
ChecksumHelperShmemInit(void)
{
	bool		found;

	ChecksumHelperShmem = (ChecksumHelperShmemStruct *)
		ShmemInitStruct("ChecksumHelper Data",
						ChecksumHelperShmemSize(),
						&found);

	if (!found)
	{
		MemSet(ChecksumHelperShmem, 0, ChecksumHelperShmemSize());
	}
}

/*
 * BuildDatabaseList
 *		Compile a list of all currently available databases in the cluster
 *
 * This creates the list of databases for the checksumhelper workers to add
 * checksums to.
 */
static List *
BuildDatabaseList(void)
{
	List	   *DatabaseList = NIL;
	Relation	rel;
	TableScanDesc scan;
	HeapTuple	tup;
	MemoryContext ctx = CurrentMemoryContext;
	MemoryContext oldctx;

	StartTransactionCommand();

	rel = table_open(DatabaseRelationId, AccessShareLock);

	/*
	 * Before we do this, wait for all pending transactions to finish. This
	 * will ensure there are no concurrently running CREATE DATABASE, which
	 * could cause us to miss the creation of a database that was copied
	 * without checksums.
	 */
	WaitForAllTransactionsToFinish();

	scan = table_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_database pgdb = (Form_pg_database) GETSTRUCT(tup);
		ChecksumHelperDatabase *db;

		/*
		 * If this database has been checksummed already, don't consider it
		 * when compiling the list to checksum.
		 */
		if (pgdb->dathaschecksums)
			continue;

		oldctx = MemoryContextSwitchTo(ctx);

		db = (ChecksumHelperDatabase *) palloc(sizeof(ChecksumHelperDatabase));

		db->dboid = pgdb->oid;
		db->dbname = pstrdup(NameStr(pgdb->datname));

		DatabaseList = lappend(DatabaseList, db);

		MemoryContextSwitchTo(oldctx);
	}

	table_endscan(scan);
	table_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return DatabaseList;
}

/*
 * BuildRelationList
 *		Compile a list of all relations in the database
 *
 * If shared is true, both shared relations and local ones are returned, else
 * all non-shared relations are returned.
 * Temp tables are not included.
 */
static List *
BuildRelationList(bool include_shared)
{
	List	   *RelationList = NIL;
	Relation	rel;
	TableScanDesc scan;
	HeapTuple	tup;
	MemoryContext ctx = CurrentMemoryContext;
	MemoryContext oldctx;

	StartTransactionCommand();

	rel = table_open(RelationRelationId, AccessShareLock);
	scan = table_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_class pgc = (Form_pg_class) GETSTRUCT(tup);
		ChecksumHelperRelation *relentry;

		if (pgc->relpersistence == RELPERSISTENCE_TEMP)
			continue;

		if (pgc->relisshared && !include_shared)
			continue;

		/*
		 * Only include relations types that have local storage
		 */
		if (pgc->relkind == RELKIND_VIEW ||
			pgc->relkind == RELKIND_COMPOSITE_TYPE ||
			pgc->relkind == RELKIND_FOREIGN_TABLE)
			continue;

		oldctx = MemoryContextSwitchTo(ctx);
		relentry = (ChecksumHelperRelation *) palloc(sizeof(ChecksumHelperRelation));

		relentry->reloid = pgc->oid;
		relentry->relkind = pgc->relkind;

		RelationList = lappend(RelationList, relentry);

		MemoryContextSwitchTo(oldctx);
	}

	table_endscan(scan);
	table_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return RelationList;
}

/*
 * BuildTempTableList
 *		Compile a list of all temporary tables in database
 *
 * Returns a List of oids.
 */
static List *
BuildTempTableList(void)
{
	List	   *RelationList = NIL;
	Relation	rel;
	TableScanDesc scan;
	HeapTuple	tup;
	MemoryContext ctx = CurrentMemoryContext;
	MemoryContext oldctx;

	StartTransactionCommand();

	rel = table_open(RelationRelationId, AccessShareLock);
	scan = table_beginscan_catalog(rel, 0, NULL);

	while (HeapTupleIsValid(tup = heap_getnext(scan, ForwardScanDirection)))
	{
		Form_pg_class pgc = (Form_pg_class) GETSTRUCT(tup);

		if (pgc->relpersistence != RELPERSISTENCE_TEMP)
			continue;

		oldctx = MemoryContextSwitchTo(ctx);
		RelationList = lappend_oid(RelationList, pgc->oid);
		MemoryContextSwitchTo(oldctx);
	}

	table_endscan(scan);
	table_close(rel, AccessShareLock);

	CommitTransactionCommand();

	return RelationList;
}

/*
 * Main function for enabling checksums in a single database
 */
void
ChecksumHelperWorkerMain(Datum arg)
{
	Oid			dboid = DatumGetObjectId(arg);
	List	   *RelationList = NIL;
	List	   *InitialTempTableList = NIL;
	ListCell   *lc;
	BufferAccessStrategy strategy;
	bool		aborted = false;

	pqsignal(SIGTERM, die);

	BackgroundWorkerUnblockSignals();

	MyBackendType = B_CHECKSUMHELPER_WORKER;
	init_ps_display(NULL);

	SyncLocal();

	ereport(DEBUG1,
			(errmsg("background worker \"checksumhelper\" starting for database oid %d",
					dboid)));

	BackgroundWorkerInitializeConnectionByOid(dboid, InvalidOid, BGWORKER_BYPASS_ALLOWCONN);

	/*
	 * Get a list of all temp tables present as we start in this database. We
	 * need to wait until they are all gone until we are done, since we cannot
	 * access those files and modify them.
	 */
	InitialTempTableList = BuildTempTableList();

	/*
	 * Enable vacuum cost delay, if any.
	 */
	VacuumCostDelay = ChecksumHelperShmem->cost_delay;
	VacuumCostLimit = ChecksumHelperShmem->cost_limit;
	VacuumCostActive = (VacuumCostDelay > 0);
	VacuumCostBalance = 0;
	VacuumPageHit = 0;
	VacuumPageMiss = 0;
	VacuumPageDirty = 0;

	/*
	 * Create and set the vacuum strategy as our buffer strategy.
	 */
	strategy = GetAccessStrategy(BAS_VACUUM);

	RelationList = BuildRelationList(ChecksumHelperShmem->process_shared_catalogs);
	foreach(lc, RelationList)
	{
		ChecksumHelperRelation *rel = (ChecksumHelperRelation *) lfirst(lc);

		if (!ProcessSingleRelationByOid(rel->reloid, strategy))
		{
			aborted = true;
			break;
		}
	}
	list_free_deep(RelationList);

	if (aborted)
	{
		ChecksumHelperShmem->success = CHECKSUMHELPER_ABORTED;
		ereport(DEBUG1,
				(errmsg("background worker \"checksumhelper\" aborted in database oid %d",
						dboid)));
		return;
	}

	/*
	 * Wait for all temp tables that existed when we started to go away. This
	 * is necessary since we cannot "reach" them to enable checksums. Any temp
	 * tables created after we started will already have checksums in them
	 * (due to the inprogress state), so those are safe.
	 */
	while (true)
	{
		List	   *CurrentTempTables;
		ListCell   *lc;
		int			numleft;
		char		activity[64];

		CurrentTempTables = BuildTempTableList();
		numleft = 0;
		foreach(lc, InitialTempTableList)
		{
			if (list_member_oid(CurrentTempTables, lfirst_oid(lc)))
				numleft++;
		}
		list_free(CurrentTempTables);

		if (numleft == 0)
			break;

		/* At least one temp table left to wait for */
		snprintf(activity, sizeof(activity), "Waiting for %d temp tables to be removed", numleft);
		pgstat_report_activity(STATE_RUNNING, activity);

		/* Retry every 5 seconds */
		ResetLatch(MyLatch);
		(void) WaitLatch(MyLatch,
						 WL_LATCH_SET | WL_TIMEOUT,
						 5000,
						 WAIT_EVENT_CHECKSUM_ENABLE_STARTCONDITION);
	}

	list_free(InitialTempTableList);

	SetDatabaseChecksumFlag(dboid);
	ChecksumHelperShmem->success = CHECKSUMHELPER_SUCCESSFUL;
	ereport(DEBUG1,
			(errmsg("background worker \"checksumhelper\" completed in database oid %d",
					dboid)));

}
