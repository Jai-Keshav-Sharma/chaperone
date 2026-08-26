//! Embedded migration runner.
//!
//! Applies `migrations/001_initial_schema.sql` on first connection. The
//! migration is immutable once committed (Law 5 spirit: append-only schema
//! evolution).

use sqlx::migrate::Migrator;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Run all pending migrations. Idempotent — safe to call on every startup.
pub async fn run_migrations(conn: &sqlx::SqlitePool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(conn).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn migrations_are_idempotent(pool: sqlx::SqlitePool) {
        run_migrations(&pool).await.expect("first run");
        run_migrations(&pool)
            .await
            .expect("second run is idempotent");
    }
}
