//! Poison-recovering Mutex/RwLock extension traits, split from router/mod.rs.
use super::*;

/// Extension trait that recovers from poisoned mutexes instead of panicking.
/// If a thread panicked while holding a lock, we log an error, bump the
/// poison counter, and continue — better than a cascade crash from an
/// unrelated panic. Operators must monitor `norn_mutex_poison_total` and
/// investigate any non-zero value: data behind the lock may be inconsistent.
pub(crate) trait LockOrRecover<T> {
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T>;
}

impl<T> LockOrRecover<T> for std::sync::Mutex<T> {
    #[track_caller]
    fn lock_or_recover(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|p| {
            // track_caller surfaces the lock_or_recover call site in the log
            // so operators see WHERE the inconsistency was first observed.
            let loc = std::panic::Location::caller();
            MUTEX_POISON_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                file = loc.file(), line = loc.line(),
                "mutex poisoned at {}:{} — RECOVERING but state may be inconsistent. \
                 Check norn_mutex_poison_total in /metrics; non-zero is a red flag.",
                loc.file(), loc.line(),
            );
            p.into_inner()
        })
    }
}

/// Same poison-recovery story for `RwLock`, used by
/// [`SharedSessionManager`]: hot-path encrypt/decrypt take a
/// `read_or_recover()` so N peers run AEAD concurrently; setup
/// (handle_init/handle_ack/initiate/remove) takes
/// `write_or_recover()`.
pub(crate) trait RwLockOrRecover<T> {
    fn read_or_recover(&self) -> std::sync::RwLockReadGuard<'_, T>;
    fn write_or_recover(&self) -> std::sync::RwLockWriteGuard<'_, T>;
}

impl<T> RwLockOrRecover<T> for std::sync::RwLock<T> {
    #[track_caller]
    fn read_or_recover(&self) -> std::sync::RwLockReadGuard<'_, T> {
        self.read().unwrap_or_else(|p| {
            let loc = std::panic::Location::caller();
            MUTEX_POISON_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                file = loc.file(), line = loc.line(),
                "rwlock poisoned (read) at {}:{} — RECOVERING but state may be inconsistent",
                loc.file(), loc.line(),
            );
            p.into_inner()
        })
    }

    #[track_caller]
    fn write_or_recover(&self) -> std::sync::RwLockWriteGuard<'_, T> {
        self.write().unwrap_or_else(|p| {
            let loc = std::panic::Location::caller();
            MUTEX_POISON_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::error!(
                file = loc.file(), line = loc.line(),
                "rwlock poisoned (write) at {}:{} — RECOVERING but state may be inconsistent",
                loc.file(), loc.line(),
            );
            p.into_inner()
        })
    }
}
