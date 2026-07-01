//! `/dev/diag` device bringup — independent implementation, scoped to the
//! Orbic RC400L specifically (this MVP targets one device, not a general
//! device-abstraction layer).
//!
//! The ioctl request numbers and the "memory device mode" constant are
//! kernel diagnostic-driver interface facts (the same driver family is
//! visible in public AOSP MSM kernel trees, e.g.
//! `drivers/char/diag/diagchar.h`), not creative expression — reimplemented
//! from what's needed to make `ioctl(2)` succeed against this device's
//! driver, not from any GPL source's structure or types.

use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

// libc::ioctl's request-parameter type is platform-dependent (musl vs.
// glibc disagree, independent of anything protocol-related) — matches the
// real firmware target (armv7-unknown-linux-musleabihf, musl) plus
// x86_64-unknown-linux-gnu for dev-host checking.
#[cfg(target_env = "musl")]
const DIAG_IOCTL_SWITCH_LOGGING: libc::c_int = 7;
#[cfg(not(target_env = "musl"))]
const DIAG_IOCTL_SWITCH_LOGGING: libc::c_ulong = 7;
const MEMORY_DEVICE_MODE: u32 = 2;
const BUFFER_LEN: usize = 10 * 1024 * 1024;

/// Alternate ioctl argument shape some diag driver versions expect when
/// the simple form is rejected. Field layout is a kernel ABI fact, not a
/// design choice: `req_mode`/`peripheral_mask`/`mode_param`, `repr(C)` so
/// the byte layout matches what the driver reads.
#[repr(C)]
#[derive(Clone, Copy)]
struct LoggingModeParam {
    req_mode: u32,
    peripheral_mask: u32,
    mode_param: u8,
}

pub struct DiagDevice {
    file: File,
    read_buf: Vec<u8>,
}

impl DiagDevice {
    pub async fn open(path: &str) -> io::Result<Self> {
        Self::open_with_retries(path, Duration::from_secs(30)).await
    }

    pub async fn open_with_retries(path: &str, max_duration: Duration) -> io::Result<Self> {
        let start = std::time::Instant::now();
        let mut delay = Duration::from_millis(100);
        loop {
            match Self::try_open(path).await {
                Ok(dev) => return Ok(dev),
                Err(e) if start.elapsed() < max_duration => {
                    eprintln!("diag device open failed, retrying in {delay:?}: {e}");
                    sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn try_open(path: &str) -> io::Result<Self> {
        let file = File::options().read(true).write(true).open(path).await?;
        switch_logging_mode(file.as_raw_fd(), MEMORY_DEVICE_MODE)?;
        Ok(Self {
            file,
            read_buf: vec![0u8; BUFFER_LEN],
        })
    }

    /// Reads the next raw buffer's worth of bytes off the device.
    /// Tolerates short reads (some devices return only a handful of bytes
    /// right after the mode switch) by retrying until a substantive read
    /// arrives, rather than handing tiny fragments to the caller.
    pub async fn read_raw(&mut self) -> io::Result<&[u8]> {
        let mut n = 0usize;
        while n <= 8 {
            n = self.file.read(&mut self.read_buf).await?;
        }
        Ok(&self.read_buf[..n])
    }

    /// Writes a fully-framed request buffer to the device. Some diag char
    /// device implementations report a zero-byte write on success (the
    /// write is still interpreted) — that's tolerated, not treated as
    /// failure.
    pub async fn write_raw(&mut self, buf: &[u8]) -> io::Result<()> {
        match self.file.write(buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WriteZero => {}
            Err(e) => return Err(e),
        }
        match self.file.flush().await {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::WriteZero => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}

fn switch_logging_mode(fd: i32, mode: u32) -> io::Result<()> {
    // Try the simple form first: mode as a direct ioctl argument.
    let simple = unsafe { libc::ioctl(fd, DIAG_IOCTL_SWITCH_LOGGING, mode, 0, 0, 0) };
    if simple >= 0 {
        return Ok(());
    }

    // Some driver versions instead expect a struct argument.
    let mut param = LoggingModeParam {
        req_mode: mode,
        peripheral_mask: u32::MAX,
        mode_param: 0,
    };
    let structured = unsafe {
        libc::ioctl(
            fd,
            DIAG_IOCTL_SWITCH_LOGGING,
            &mut param as *mut LoggingModeParam,
            std::mem::size_of::<LoggingModeParam>(),
            0,
            0,
            0,
            0,
        )
    };
    if structured >= 0 {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "DIAG_IOCTL_SWITCH_LOGGING failed (simple form: {simple}, structured form: {structured})"
    )))
}
