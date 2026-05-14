//! Shared terminal helpers for TTY-mode I/O proxying.
//!
//! Provides raw mode management, SIGWINCH handling, and terminal
//! cleanup signal handlers. Used by both the `vm exec` path and
//! the `arapuca run -t` path.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

// ─── Raw mode guard ───────────────────────────────────────────

// SAFETY: CLEANUP_TERMIOS is written once (before signal handler
// install) and read only from the signal handler (after the write).
// libc::termios is a plain C struct (Copy, no pointers). Access
// uses addr_of_mut! to avoid creating references to static mut
// (Rust 2024 edition compliance).
static mut CLEANUP_TERMIOS: libc::termios = unsafe { std::mem::zeroed() };
pub(crate) static CLEANUP_FD: AtomicI32 = AtomicI32::new(-1);

pub(crate) struct RawModeGuard {
    fd: i32,
    saved: libc::termios,
}

impl RawModeGuard {
    /// Enter raw mode on the given fd.
    ///
    /// Saves the current termios for signal handler cleanup. The
    /// caller is responsible for installing signal handlers (either
    /// `install_cleanup_signal_handlers` or a custom handler that
    /// calls `restore_termios`).
    pub(crate) fn enter(fd: i32) -> std::io::Result<Self> {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: tcgetattr on a valid fd.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Store for signal handler cleanup (before handler install).
        // SAFETY: single-threaded at this point, written before
        // signal handlers are installed.
        unsafe { std::ptr::addr_of_mut!(CLEANUP_TERMIOS).write(saved) };
        CLEANUP_FD.store(fd, Ordering::Release);

        let mut raw = saved;
        // SAFETY: cfmakeraw modifies the termios struct in place.
        unsafe { libc::cfmakeraw(&mut raw) };
        // SAFETY: tcsetattr on a valid fd.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { fd, saved })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // SAFETY: restoring saved termios.
        unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved) };
        CLEANUP_FD.store(-1, Ordering::Release);
    }
}

/// Restore terminal state from the saved CLEANUP_TERMIOS.
///
/// Async-signal-safe. Does nothing if CLEANUP_FD is -1 (raw mode
/// not active). This is the building block for signal handlers —
/// it does NOT re-raise or exit.
pub(crate) fn restore_termios() {
    let fd = CLEANUP_FD.load(Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: tcsetattr is async-signal-safe per POSIX.
        // CLEANUP_TERMIOS was written before the signal handler
        // was installed; the sigaction call provides a memory barrier.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(CLEANUP_TERMIOS));
        }
    }
}

/// Install signal handlers that restore terminal state and re-raise.
///
/// Used by `vm exec` which doesn't need child signal forwarding.
/// For `arapuca run -t`, use `restore_termios()` as a building
/// block in a custom handler instead.
pub(crate) fn install_cleanup_signal_handlers() {
    extern "C" fn cleanup_handler(sig: libc::c_int) {
        restore_termios();
        // Re-raise with default disposition for correct exit status.
        // SAFETY: signal + raise are async-signal-safe.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    // SAFETY: handler is async-signal-safe (tcsetattr, signal, raise).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = cleanup_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGQUIT, &sa, std::ptr::null_mut());
    }
}

// ─── SIGWINCH ─────────────────────────────────────────────────

pub(crate) static SIGWINCH_RECEIVED: AtomicBool = AtomicBool::new(false);

pub(crate) fn install_sigwinch_handler() {
    extern "C" fn handler(_sig: libc::c_int) {
        SIGWINCH_RECEIVED.store(true, Ordering::Release);
    }
    // SAFETY: handler only sets an AtomicBool — async-signal-safe.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGWINCH, &sa, std::ptr::null_mut());
    }
}

// ─── Terminal helpers ─────────────────────────────────────────

pub(crate) fn get_terminal_size() -> (u16, u16) {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ on stdin.
    let ret = unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        (ws.ws_row, ws.ws_col)
    } else {
        (24, 80)
    }
}
