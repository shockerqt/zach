use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt;
use std::path::Path;
use std::ptr;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;
const SQLITE_OPEN_FULLMUTEX: c_int = 0x0001_0000;

type SqliteCallback =
    Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>;

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        db: *mut *mut c_void,
        flags: c_int,
        vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close(db: *mut c_void) -> c_int;
    fn sqlite3_errmsg(db: *mut c_void) -> *const c_char;
    fn sqlite3_exec(
        db: *mut c_void,
        sql: *const c_char,
        callback: SqliteCallback,
        argument: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_prepare_v2(
        db: *mut c_void,
        sql: *const c_char,
        bytes: c_int,
        statement: *mut *mut c_void,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_finalize(statement: *mut c_void) -> c_int;
    fn sqlite3_step(statement: *mut c_void) -> c_int;
    fn sqlite3_bind_text(
        statement: *mut c_void,
        index: c_int,
        value: *const c_char,
        bytes: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn sqlite3_bind_int64(statement: *mut c_void, index: c_int, value: i64) -> c_int;
    fn sqlite3_column_text(statement: *mut c_void, column: c_int) -> *const u8;
    fn sqlite3_column_int64(statement: *mut c_void, column: c_int) -> i64;
    fn sqlite3_changes(db: *mut c_void) -> c_int;
    fn sqlite3_busy_timeout(db: *mut c_void, milliseconds: c_int) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Claim {
    Execute,
    Replay {
        terminal_receipt: String,
        terminal_result_id: String,
    },
    InFlight,
    AmbiguousRecovery,
    RequestConflict,
    IssueRequestFrozen,
    DeliveryConflict,
}

pub(super) struct ClaimInput<'a> {
    pub request_id: &'a str,
    pub request_digest: &'a str,
    pub issue_number: i64,
    pub canonical_request: &'a str,
    pub canonical_identity: &'a str,
    pub delivery_id: &'a str,
    pub instance_id: &'a str,
    pub now_epoch: i64,
    pub lease_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PublicationClaim {
    Publish,
    InFlight,
    Reconcile,
    Sent(i64),
}

pub(super) struct SqliteStore {
    db: *mut c_void,
}

impl SqliteStore {
    pub(super) fn open(path: &Path) -> Result<Self, StoreError> {
        let filename = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| StoreError("SQLite path contains NUL".into()))?;
        let mut db = ptr::null_mut();
        // SAFETY: filename is NUL-terminated and db points to writable storage for SQLite's handle.
        let status = unsafe {
            sqlite3_open_v2(
                filename.as_ptr(),
                &mut db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                ptr::null(),
            )
        };
        if status != SQLITE_OK || db.is_null() {
            let message = if db.is_null() {
                format!("sqlite3_open_v2 failed with status {status}")
            } else {
                sqlite_error(db)
            };
            if !db.is_null() {
                // SAFETY: SQLite returned a non-null handle which must be closed on open failure.
                unsafe {
                    sqlite3_close(db);
                }
            }
            return Err(StoreError(message));
        }
        // SAFETY: db is a live SQLite connection.
        let busy = unsafe { sqlite3_busy_timeout(db, 5_000) };
        if busy != SQLITE_OK {
            let message = sqlite_error(db);
            // SAFETY: db is a live SQLite connection owned by this function.
            unsafe {
                sqlite3_close(db);
            }
            return Err(StoreError(message));
        }
        let store = Self { db };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<(), StoreError> {
        self.exec(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=FULL;\n\
             PRAGMA foreign_keys=ON;\n\
             CREATE TABLE IF NOT EXISTS issue_bindings (\n\
               issue_number INTEGER PRIMARY KEY,\n\
               request_id TEXT NOT NULL,\n\
               request_digest TEXT NOT NULL,\n\
               canonical_request_identity TEXT NOT NULL,\n\
               canonical_request TEXT NOT NULL\n\
             );\n\
             CREATE TABLE IF NOT EXISTS transactions (\n\
               request_id TEXT PRIMARY KEY,\n\
               request_digest TEXT NOT NULL,\n\
               issue_number INTEGER NOT NULL UNIQUE,\n\
               canonical_request_identity TEXT NOT NULL,\n\
               canonical_request TEXT NOT NULL,\n\
               state TEXT NOT NULL CHECK(state IN ('executing','recovering','terminal')),\n\
               owner_instance TEXT NOT NULL,\n\
               lease_until INTEGER NOT NULL,\n\
               accepted_epoch INTEGER NOT NULL,\n\
               terminal_receipt TEXT,\n\
               terminal_result_id TEXT,\n\
               publication_state TEXT NOT NULL DEFAULT 'pending' CHECK(publication_state IN ('pending','sending','sent')),\n\
               publication_owner TEXT,\n\
               publication_lease_until INTEGER NOT NULL DEFAULT 0,\n\
               publication_comment_id INTEGER,\n\
               FOREIGN KEY(issue_number) REFERENCES issue_bindings(issue_number)\n\
             );\n\
             CREATE TABLE IF NOT EXISTS deliveries (\n\
               delivery_id TEXT PRIMARY KEY,\n\
               request_id TEXT NOT NULL,\n\
               request_digest TEXT NOT NULL,\n\
               issue_number INTEGER NOT NULL,\n\
               first_seen_epoch INTEGER NOT NULL,\n\
               FOREIGN KEY(request_id) REFERENCES transactions(request_id)\n\
             );",
        )
    }

    pub(super) fn claim(&mut self, input: &ClaimInput<'_>) -> Result<Claim, StoreError> {
        self.transaction(|store| store.claim_inside(input))
    }

    fn claim_inside(&mut self, input: &ClaimInput<'_>) -> Result<Claim, StoreError> {
        if let Some((request_id, digest, issue)) = self.delivery(input.delivery_id)?
            && (request_id != input.request_id
                || digest != input.request_digest
                || issue != input.issue_number)
        {
            return Ok(Claim::DeliveryConflict);
        }

        let issue = self.issue_binding(input.issue_number)?;
        if let Some(binding) = &issue
            && (binding.request_id != input.request_id
                || binding.request_digest != input.request_digest
                || binding.canonical_identity != input.canonical_identity
                || binding.canonical_request != input.canonical_request)
        {
            return Ok(Claim::IssueRequestFrozen);
        }

        let transaction = self.transaction_row(input.request_id)?;
        if let Some(row) = &transaction {
            if row.request_digest != input.request_digest {
                return Ok(Claim::RequestConflict);
            }
            if row.issue_number != input.issue_number
                || row.canonical_identity != input.canonical_identity
                || row.canonical_request != input.canonical_request
            {
                return Ok(Claim::RequestConflict);
            }
            if issue.is_none() {
                return Err(StoreError(
                    "SQLite transaction exists without its issue binding".into(),
                ));
            }
            self.ensure_delivery(input)?;
            if row.state == "terminal" {
                let receipt = row.terminal_receipt.clone().ok_or_else(|| {
                    StoreError("terminal SQLite transaction has no persisted receipt".into())
                })?;
                let result_id = row.terminal_result_id.clone().ok_or_else(|| {
                    StoreError(
                        "terminal SQLite transaction has no persisted result identity".into(),
                    )
                })?;
                return Ok(Claim::Replay {
                    terminal_receipt: receipt,
                    terminal_result_id: result_id,
                });
            }
            if row.lease_until > input.now_epoch {
                return Ok(Claim::InFlight);
            }
            let lease_until = input.now_epoch.saturating_add(input.lease_seconds.max(1));
            let mut statement = self.prepare(
                "UPDATE transactions SET state='recovering', owner_instance=?1, lease_until=?2 \
                 WHERE request_id=?3 AND request_digest=?4 AND state IN ('executing','recovering')",
            )?;
            statement.bind_text(1, input.instance_id)?;
            statement.bind_i64(2, lease_until)?;
            statement.bind_text(3, input.request_id)?;
            statement.bind_text(4, input.request_digest)?;
            statement.done()?;
            if self.changes() != 1 {
                return Err(StoreError(
                    "ambiguous recovery claim lost its serialized SQLite update".into(),
                ));
            }
            return Ok(Claim::AmbiguousRecovery);
        }

        if issue.is_some() {
            return Err(StoreError(
                "SQLite issue binding exists without its logical transaction".into(),
            ));
        }

        let mut issue_statement = self.prepare(
            "INSERT INTO issue_bindings(\
               issue_number,request_id,request_digest,canonical_request_identity,canonical_request\
             ) VALUES(?1,?2,?3,?4,?5)",
        )?;
        issue_statement.bind_i64(1, input.issue_number)?;
        issue_statement.bind_text(2, input.request_id)?;
        issue_statement.bind_text(3, input.request_digest)?;
        issue_statement.bind_text(4, input.canonical_identity)?;
        issue_statement.bind_text(5, input.canonical_request)?;
        issue_statement.done()?;
        drop(issue_statement);

        let lease_until = input.now_epoch.saturating_add(input.lease_seconds.max(1));
        let mut transaction_statement = self.prepare(
            "INSERT INTO transactions(\
               request_id,request_digest,issue_number,canonical_request_identity,canonical_request,\
               state,owner_instance,lease_until,accepted_epoch\
             ) VALUES(?1,?2,?3,?4,?5,'executing',?6,?7,?8)",
        )?;
        transaction_statement.bind_text(1, input.request_id)?;
        transaction_statement.bind_text(2, input.request_digest)?;
        transaction_statement.bind_i64(3, input.issue_number)?;
        transaction_statement.bind_text(4, input.canonical_identity)?;
        transaction_statement.bind_text(5, input.canonical_request)?;
        transaction_statement.bind_text(6, input.instance_id)?;
        transaction_statement.bind_i64(7, lease_until)?;
        transaction_statement.bind_i64(8, input.now_epoch)?;
        transaction_statement.done()?;
        drop(transaction_statement);
        self.ensure_delivery(input)?;
        Ok(Claim::Execute)
    }

    pub(super) fn complete(
        &mut self,
        request_id: &str,
        request_digest: &str,
        instance_id: &str,
        terminal_receipt: &str,
        terminal_result_id: &str,
    ) -> Result<(), StoreError> {
        self.transaction(|store| {
            let mut statement = store.prepare(
                "UPDATE transactions SET state='terminal', lease_until=0, terminal_receipt=?1, \
                 terminal_result_id=?2, publication_state='pending', publication_owner=NULL, \
                 publication_lease_until=0, publication_comment_id=NULL \
                 WHERE request_id=?3 AND request_digest=?4 AND owner_instance=?5 \
                   AND state IN ('executing','recovering')",
            )?;
            statement.bind_text(1, terminal_receipt)?;
            statement.bind_text(2, terminal_result_id)?;
            statement.bind_text(3, request_id)?;
            statement.bind_text(4, request_digest)?;
            statement.bind_text(5, instance_id)?;
            statement.done()?;
            drop(statement);
            if store.changes() != 1 {
                return Err(StoreError(
                    "terminal SQLite write lost ownership or did not match one transaction".into(),
                ));
            }
            Ok(())
        })
    }

    pub(super) fn claim_publication(
        &mut self,
        request_id: &str,
        request_digest: &str,
        instance_id: &str,
        now_epoch: i64,
        lease_seconds: i64,
    ) -> Result<PublicationClaim, StoreError> {
        self.transaction(|store| {
            let row = store.transaction_row(request_id)?.ok_or_else(|| {
                StoreError("publication requested for unknown transaction".into())
            })?;
            if row.request_digest != request_digest || row.state != "terminal" {
                return Err(StoreError(
                    "publication requested for non-terminal or mismatched transaction".into(),
                ));
            }
            let publication = store.publication_row(request_id)?;
            match publication.state.as_str() {
                "sent" => publication
                    .comment_id
                    .map(PublicationClaim::Sent)
                    .ok_or_else(|| StoreError("sent publication has no comment id".into())),
                "sending" if publication.lease_until > now_epoch => {
                    Ok(PublicationClaim::InFlight)
                }
                "sending" => Ok(PublicationClaim::Reconcile),
                "pending" => {
                    let lease_until = now_epoch.saturating_add(lease_seconds.max(1));
                    let mut statement = store.prepare(
                        "UPDATE transactions SET publication_state='sending', publication_owner=?1, \
                         publication_lease_until=?2 WHERE request_id=?3 AND request_digest=?4 \
                         AND state='terminal' AND publication_state='pending'",
                    )?;
                    statement.bind_text(1, instance_id)?;
                    statement.bind_i64(2, lease_until)?;
                    statement.bind_text(3, request_id)?;
                    statement.bind_text(4, request_digest)?;
                    statement.done()?;
                    drop(statement);
                    if store.changes() != 1 {
                        return Err(StoreError("publication claim update was not unique".into()));
                    }
                    Ok(PublicationClaim::Publish)
                }
                other => Err(StoreError(format!(
                    "unknown publication state {other}"
                ))),
            }
        })
    }

    pub(super) fn mark_published(
        &mut self,
        request_id: &str,
        request_digest: &str,
        instance_id: &str,
        comment_id: i64,
    ) -> Result<(), StoreError> {
        self.transaction(|store| {
            let mut statement = store.prepare(
                "UPDATE transactions SET publication_state='sent', publication_comment_id=?1, \
                 publication_owner=NULL, publication_lease_until=0 \
                 WHERE request_id=?2 AND request_digest=?3 \
                 AND publication_state='sending' AND publication_owner=?4 AND state='terminal'",
            )?;
            statement.bind_i64(1, comment_id)?;
            statement.bind_text(2, request_id)?;
            statement.bind_text(3, request_digest)?;
            statement.bind_text(4, instance_id)?;
            statement.done()?;
            drop(statement);
            if store.changes() == 1 {
                return Ok(());
            }
            let publication = store.publication_row(request_id)?;
            if publication.state == "sent" && publication.comment_id == Some(comment_id) {
                Ok(())
            } else {
                Err(StoreError(
                    "published comment could not be bound to its SQLite outbox claim".into(),
                ))
            }
        })
    }

    pub(super) fn mark_reconciled(
        &mut self,
        request_id: &str,
        request_digest: &str,
        comment_id: i64,
    ) -> Result<(), StoreError> {
        self.transaction(|store| {
            let mut statement = store.prepare(
                "UPDATE transactions SET publication_state='sent', publication_comment_id=?1, \
                 publication_owner=NULL, publication_lease_until=0 \
                 WHERE request_id=?2 AND request_digest=?3 \
                 AND publication_state='sending' AND state='terminal'",
            )?;
            statement.bind_i64(1, comment_id)?;
            statement.bind_text(2, request_id)?;
            statement.bind_text(3, request_digest)?;
            statement.done()?;
            drop(statement);
            if store.changes() == 1 {
                return Ok(());
            }
            let publication = store.publication_row(request_id)?;
            if publication.state == "sent" && publication.comment_id == Some(comment_id) {
                Ok(())
            } else {
                Err(StoreError(
                    "trusted reconciled comment could not be bound to its SQLite outbox".into(),
                ))
            }
        })
    }

    fn delivery(&self, delivery_id: &str) -> Result<Option<(String, String, i64)>, StoreError> {
        let mut statement = self.prepare(
            "SELECT request_id,request_digest,issue_number FROM deliveries WHERE delivery_id=?1",
        )?;
        statement.bind_text(1, delivery_id)?;
        if statement.row()? {
            Ok(Some((
                statement
                    .text(0)?
                    .ok_or_else(|| StoreError("delivery request_id is NULL".into()))?,
                statement
                    .text(1)?
                    .ok_or_else(|| StoreError("delivery digest is NULL".into()))?,
                statement.i64(2),
            )))
        } else {
            Ok(None)
        }
    }

    fn ensure_delivery(&self, input: &ClaimInput<'_>) -> Result<(), StoreError> {
        if self.delivery(input.delivery_id)?.is_some() {
            return Ok(());
        }
        let mut statement = self.prepare(
            "INSERT INTO deliveries(delivery_id,request_id,request_digest,issue_number,first_seen_epoch) \
             VALUES(?1,?2,?3,?4,?5)",
        )?;
        statement.bind_text(1, input.delivery_id)?;
        statement.bind_text(2, input.request_id)?;
        statement.bind_text(3, input.request_digest)?;
        statement.bind_i64(4, input.issue_number)?;
        statement.bind_i64(5, input.now_epoch)?;
        statement.done()
    }

    fn issue_binding(&self, issue_number: i64) -> Result<Option<IssueBinding>, StoreError> {
        let mut statement = self.prepare(
            "SELECT request_id,request_digest,canonical_request_identity,canonical_request \
             FROM issue_bindings WHERE issue_number=?1",
        )?;
        statement.bind_i64(1, issue_number)?;
        if !statement.row()? {
            return Ok(None);
        }
        Ok(Some(IssueBinding {
            request_id: required_text(&statement, 0, "issue request_id")?,
            request_digest: required_text(&statement, 1, "issue request_digest")?,
            canonical_identity: required_text(&statement, 2, "issue canonical identity")?,
            canonical_request: required_text(&statement, 3, "issue canonical request")?,
        }))
    }

    fn transaction_row(&self, request_id: &str) -> Result<Option<TransactionRow>, StoreError> {
        let mut statement = self.prepare(
            "SELECT request_digest,issue_number,canonical_request_identity,canonical_request,state,\
             owner_instance,lease_until,terminal_receipt,terminal_result_id \
             FROM transactions WHERE request_id=?1",
        )?;
        statement.bind_text(1, request_id)?;
        if !statement.row()? {
            return Ok(None);
        }
        Ok(Some(TransactionRow {
            request_digest: required_text(&statement, 0, "transaction request_digest")?,
            issue_number: statement.i64(1),
            canonical_identity: required_text(&statement, 2, "transaction canonical identity")?,
            canonical_request: required_text(&statement, 3, "transaction canonical request")?,
            state: required_text(&statement, 4, "transaction state")?,
            owner_instance: required_text(&statement, 5, "transaction owner")?,
            lease_until: statement.i64(6),
            terminal_receipt: statement.text(7)?,
            terminal_result_id: statement.text(8)?,
        }))
    }

    fn publication_row(&self, request_id: &str) -> Result<PublicationRow, StoreError> {
        let mut statement = self.prepare(
            "SELECT publication_state,publication_lease_until,publication_comment_id \
             FROM transactions WHERE request_id=?1",
        )?;
        statement.bind_text(1, request_id)?;
        if !statement.row()? {
            return Err(StoreError("publication transaction disappeared".into()));
        }
        Ok(PublicationRow {
            state: required_text(&statement, 0, "publication state")?,
            lease_until: statement.i64(1),
            comment_id: statement
                .text(2)?
                .map(|value| value.parse())
                .transpose()
                .map_err(|_| StoreError("publication comment id is invalid".into()))?,
        })
    }

    fn transaction<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.exec("BEGIN IMMEDIATE")?;
        match operation(self) {
            Ok(value) => {
                if let Err(error) = self.exec("COMMIT") {
                    let _ = self.exec("ROLLBACK");
                    Err(error)
                } else {
                    Ok(value)
                }
            }
            Err(error) => {
                let _ = self.exec("ROLLBACK");
                Err(error)
            }
        }
    }

    fn exec(&self, sql: &str) -> Result<(), StoreError> {
        let sql = CString::new(sql).map_err(|_| StoreError("SQLite SQL contains NUL".into()))?;
        // SAFETY: db is live for Self's lifetime; SQL is NUL-terminated; no callback/output pointer is used.
        let status = unsafe {
            sqlite3_exec(
                self.db,
                sql.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status == SQLITE_OK {
            Ok(())
        } else {
            Err(StoreError(sqlite_error(self.db)))
        }
    }

    fn prepare(&self, sql: &str) -> Result<Statement, StoreError> {
        let sql = CString::new(sql).map_err(|_| StoreError("SQLite SQL contains NUL".into()))?;
        let mut statement = ptr::null_mut();
        // SAFETY: db is live and SQL is NUL-terminated; statement points to writable handle storage.
        let status = unsafe {
            sqlite3_prepare_v2(self.db, sql.as_ptr(), -1, &mut statement, ptr::null_mut())
        };
        if status != SQLITE_OK || statement.is_null() {
            Err(StoreError(sqlite_error(self.db)))
        } else {
            Ok(Statement {
                db: self.db,
                statement,
                bound_text: Vec::new(),
            })
        }
    }

    fn changes(&self) -> c_int {
        // SAFETY: db is live for Self's lifetime.
        unsafe { sqlite3_changes(self.db) }
    }
}

impl Drop for SqliteStore {
    fn drop(&mut self) {
        if !self.db.is_null() {
            // SAFETY: this object exclusively owns the live connection and drops after all statements.
            unsafe {
                sqlite3_close(self.db);
            }
            self.db = ptr::null_mut();
        }
    }
}

struct IssueBinding {
    request_id: String,
    request_digest: String,
    canonical_identity: String,
    canonical_request: String,
}

struct TransactionRow {
    request_digest: String,
    issue_number: i64,
    canonical_identity: String,
    canonical_request: String,
    state: String,
    #[allow(dead_code)]
    owner_instance: String,
    lease_until: i64,
    terminal_receipt: Option<String>,
    terminal_result_id: Option<String>,
}

struct PublicationRow {
    state: String,
    lease_until: i64,
    comment_id: Option<i64>,
}

struct Statement {
    db: *mut c_void,
    statement: *mut c_void,
    bound_text: Vec<CString>,
}

impl Statement {
    fn bind_text(&mut self, index: c_int, value: &str) -> Result<(), StoreError> {
        let value =
            CString::new(value).map_err(|_| StoreError("SQLite bound text contains NUL".into()))?;
        self.bound_text.push(value);
        let pointer = self
            .bound_text
            .last()
            .expect("bound text was just pushed")
            .as_ptr();
        // SAFETY: statement is live and CString storage remains alive in bound_text through step/finalize.
        let status = unsafe { sqlite3_bind_text(self.statement, index, pointer, -1, None) };
        self.status(status)
    }

    fn bind_i64(&mut self, index: c_int, value: i64) -> Result<(), StoreError> {
        // SAFETY: statement is live and index/value are plain SQLite bind parameters.
        let status = unsafe { sqlite3_bind_int64(self.statement, index, value) };
        self.status(status)
    }

    fn row(&mut self) -> Result<bool, StoreError> {
        // SAFETY: statement is live and stepped at most until one row/done for these queries.
        match unsafe { sqlite3_step(self.statement) } {
            SQLITE_ROW => Ok(true),
            SQLITE_DONE => Ok(false),
            _ => Err(StoreError(sqlite_error(self.db))),
        }
    }

    fn done(&mut self) -> Result<(), StoreError> {
        // SAFETY: statement is live and this call consumes its DML execution result.
        match unsafe { sqlite3_step(self.statement) } {
            SQLITE_DONE => Ok(()),
            _ => Err(StoreError(sqlite_error(self.db))),
        }
    }

    fn text(&self, column: c_int) -> Result<Option<String>, StoreError> {
        // SAFETY: statement currently points at a SQLITE_ROW; SQLite owns this pointer until next step/finalize.
        let pointer = unsafe { sqlite3_column_text(self.statement, column) };
        if pointer.is_null() {
            return Ok(None);
        }
        // SAFETY: SQLite column text is NUL-terminated UTF-8 for TEXT values.
        let value = unsafe { CStr::from_ptr(pointer.cast::<c_char>()) }
            .to_str()
            .map_err(|_| StoreError("SQLite TEXT value is not UTF-8".into()))?;
        Ok(Some(value.to_owned()))
    }

    fn i64(&self, column: c_int) -> i64 {
        // SAFETY: statement currently points at a SQLITE_ROW and SQLite converts INTEGER-compatible values.
        unsafe { sqlite3_column_int64(self.statement, column) }
    }

    fn status(&self, status: c_int) -> Result<(), StoreError> {
        if status == SQLITE_OK {
            Ok(())
        } else {
            Err(StoreError(sqlite_error(self.db)))
        }
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.statement.is_null() {
            // SAFETY: this object exclusively owns the prepared statement handle.
            unsafe {
                sqlite3_finalize(self.statement);
            }
            self.statement = ptr::null_mut();
        }
    }
}

fn required_text(statement: &Statement, column: c_int, label: &str) -> Result<String, StoreError> {
    statement
        .text(column)?
        .ok_or_else(|| StoreError(format!("SQLite {label} is NULL")))
}

fn sqlite_error(db: *mut c_void) -> String {
    if db.is_null() {
        return "SQLite connection is unavailable".into();
    }
    // SAFETY: db is a live SQLite handle and sqlite3_errmsg returns a stable NUL-terminated string.
    let pointer = unsafe { sqlite3_errmsg(db) };
    if pointer.is_null() {
        return "SQLite error without message".into();
    }
    // SAFETY: sqlite3_errmsg returns valid UTF-8 in normal SQLite builds; lossy fallback avoids panics.
    unsafe { CStr::from_ptr(pointer) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    struct TestDb(PathBuf);

    impl TestDb {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "zach-ledger-store-{}-{id}.sqlite3",
                std::process::id()
            )))
        }
    }

    impl Drop for TestDb {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let _ = fs::remove_file(self.0.with_extension("sqlite3-wal"));
            let _ = fs::remove_file(self.0.with_extension("sqlite3-shm"));
        }
    }

    fn input<'a>(delivery: &'a str, instance: &'a str, now: i64) -> ClaimInput<'a> {
        ClaimInput {
            request_id: "request-0001",
            request_digest: "digest-a",
            issue_number: 7,
            canonical_request: "{\"request\":1}",
            canonical_identity: "digest-a",
            delivery_id: delivery,
            instance_id: instance,
            now_epoch: now,
            lease_seconds: 10,
        }
    }

    fn terminal_store(db: &TestDb) -> SqliteStore {
        let mut store = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            store
                .claim(&input("delivery-a", "instance-a", 100))
                .unwrap(),
            Claim::Execute
        );
        store
            .complete(
                "request-0001",
                "digest-a",
                "instance-a",
                "terminal-receipt",
                "result-a",
            )
            .unwrap();
        store
    }

    #[test]
    fn exact_replay_survives_new_sqlite_instance() {
        let db = TestDb::new();
        {
            let mut store = terminal_store(&db);
            assert_eq!(
                store
                    .claim_publication("request-0001", "digest-a", "instance-a", 100, 10)
                    .unwrap(),
                PublicationClaim::Publish
            );
            store
                .mark_published("request-0001", "digest-a", "instance-a", 77)
                .unwrap();
        }
        let mut reopened = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            reopened
                .claim(&input("delivery-b", "instance-b", 101))
                .unwrap(),
            Claim::Replay {
                terminal_receipt: "terminal-receipt".into(),
                terminal_result_id: "result-a".into(),
            }
        );
        assert_eq!(
            reopened
                .claim_publication("request-0001", "digest-a", "instance-b", 101, 10)
                .unwrap(),
            PublicationClaim::Sent(77)
        );
    }

    #[test]
    fn conflicting_request_id_is_atomic() {
        let db = TestDb::new();
        let mut store = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            store
                .claim(&input("delivery-a", "instance-a", 100))
                .unwrap(),
            Claim::Execute
        );
        let conflicting = ClaimInput {
            request_digest: "digest-b",
            issue_number: 8,
            delivery_id: "delivery-b",
            canonical_request: "{\"request\":2}",
            canonical_identity: "digest-b",
            ..input("delivery-b", "instance-b", 101)
        };
        assert_eq!(store.claim(&conflicting).unwrap(), Claim::RequestConflict);
    }

    #[test]
    fn expired_execution_lease_becomes_ambiguous_recovery_not_reexecution() {
        let db = TestDb::new();
        let mut first = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            first
                .claim(&input("delivery-a", "instance-a", 100))
                .unwrap(),
            Claim::Execute
        );
        drop(first);
        let mut restarted = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            restarted
                .claim(&input("delivery-b", "instance-b", 111))
                .unwrap(),
            Claim::AmbiguousRecovery
        );
    }

    #[test]
    fn delivery_id_is_transport_identity_not_request_identity() {
        let db = TestDb::new();
        let mut store = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            store
                .claim(&input("delivery-a", "instance-a", 100))
                .unwrap(),
            Claim::Execute
        );
        let reused_delivery = ClaimInput {
            request_id: "request-0002",
            request_digest: "digest-b",
            issue_number: 8,
            canonical_request: "{\"request\":2}",
            canonical_identity: "digest-b",
            ..input("delivery-a", "instance-b", 101)
        };
        assert_eq!(
            store.claim(&reused_delivery).unwrap(),
            Claim::DeliveryConflict
        );
    }

    #[test]
    fn expired_sending_is_reconciliation_only_and_never_grants_second_post() {
        let db = TestDb::new();
        let mut first = terminal_store(&db);
        assert_eq!(
            first
                .claim_publication("request-0001", "digest-a", "publisher-a", 100, 10)
                .unwrap(),
            PublicationClaim::Publish
        );
        drop(first);

        let mut second = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            second
                .claim_publication("request-0001", "digest-a", "publisher-b", 111, 10)
                .unwrap(),
            PublicationClaim::Reconcile
        );
        assert_eq!(
            second
                .claim_publication("request-0001", "digest-a", "publisher-c", 999, 10)
                .unwrap(),
            PublicationClaim::Reconcile
        );
    }

    #[test]
    fn trusted_reconciliation_can_persist_sent_after_original_owner_disappears() {
        let db = TestDb::new();
        let mut first = terminal_store(&db);
        assert_eq!(
            first
                .claim_publication("request-0001", "digest-a", "publisher-a", 100, 10)
                .unwrap(),
            PublicationClaim::Publish
        );
        drop(first);

        let mut restarted = SqliteStore::open(&db.0).unwrap();
        assert_eq!(
            restarted
                .claim_publication("request-0001", "digest-a", "publisher-b", 111, 10)
                .unwrap(),
            PublicationClaim::Reconcile
        );
        restarted
            .mark_reconciled("request-0001", "digest-a", 88)
            .unwrap();
        assert_eq!(
            restarted
                .claim_publication("request-0001", "digest-a", "publisher-c", 112, 10)
                .unwrap(),
            PublicationClaim::Sent(88)
        );
    }
}
