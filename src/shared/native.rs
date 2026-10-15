//! Private control messages for the native shared endpoint, outside frozen codecs.
use interprocess::local_socket::traits::Stream as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum NativeCommand {
    Enable {
        socket_path: PathBuf,
        group_gid: u32,
        policy_directory: PathBuf,
    },
    Clients,
    Refresh,
    Disable,
}

pub(crate) fn control(api: &Path, command: NativeCommand) -> io::Result<Value> {
    let mut stream = crate::ipc::connect_local_stream(api)?;
    let peer = crate::platform::local_stream_peer_identity(&stream)?;
    if peer.uid != crate::platform::effective_uid()? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native server owner mismatch",
        ));
    }
    stream.set_send_timeout(Some(Duration::from_secs(5)))?;
    stream.set_recv_timeout(Some(Duration::from_secs(5)))?;
    let request =
        json!({"id":"shared-native-control","method":"shared.native.v1","params":command});
    serde_json::to_writer(&mut stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(stream).take(65537).read_line(&mut line)?;
    if line.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native sharing control response too large",
        ));
    }
    let response: Value = serde_json::from_str(&line)?;
    response.get("result").cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native sharing control unavailable",
        )
    })
}
