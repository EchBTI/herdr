//! Linux local transport for the explicitly shared, scoped broker.

use std::{
    io::{self, Read, Write},
    path::Path,
    time::Duration,
};

#[cfg(target_os = "linux")]
#[path = "linux/shared_transport.rs"]
mod native;
#[cfg(target_os = "linux")]
pub(crate) use native::*;

#[cfg(not(target_os = "linux"))]
mod unsupported {
    use super::*;
    pub(crate) struct Listener;
    pub(crate) struct Stream;
    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "shared transport requires Linux",
        ))
    }
    pub(crate) fn bind_listener(_: &Path, _: u32) -> io::Result<Listener> {
        unsupported()
    }
    pub(crate) fn remove_socket(_: &Path) -> io::Result<()> {
        unsupported()
    }
    pub(crate) fn peer_identity(_: &Stream) -> io::Result<crate::platform::PeerIdentity> {
        unsupported()
    }
    impl Listener {
        pub(crate) fn accept(&self) -> io::Result<Stream> {
            unsupported()
        }
    }
    impl Stream {
        pub(crate) fn connect(_: &Path) -> io::Result<Self> {
            unsupported()
        }
        pub(crate) fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unsupported()
        }
        pub(crate) fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            unsupported()
        }
    }
    impl Read for Stream {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            unsupported()
        }
    }
    impl Write for Stream {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            unsupported()
        }
        fn flush(&mut self) -> io::Result<()> {
            unsupported()
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub(crate) use unsupported::*;
