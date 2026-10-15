#!/usr/bin/env python3
"""Opt-in native Herdr multi-UID qualification in a disposable Linux root container.

Run after building the binary, e.g. HERDR_SHARED_TEST_DISPOSABLE=1 python3
scripts/test_shared_access_native.py. Never mount host homes, credentials, or
account configuration. Creates only fixture accounts via test_shared_access.
Exercises the real full TUI in PTYs and the frozen generation-1 endpoint envelope.
"""
import errno
import fcntl
import json
import os
import pathlib
import pty
import re
import select
import signal
import socket
import struct
import sys
import subprocess
import termios
import time

import test_shared_access as fixture
from test_shared_access_ui import terminal_text as replay_terminal_text


WIDTH, HEIGHT = 180, 44


def terminal_text(data, width, height):
    # Native shells query terminal colors and set OSC titles using ST terminators.
    # Remove each OSC/DCS/APC independently; the legacy replay helper's greedy
    # OSC pattern would swallow the initial sidebar up to a later title update.
    clean = re.sub(rb"\x1b[\]P_^].*?(?:\x07|\x1b\\)", b"", bytes(data), flags=re.DOTALL)
    return replay_terminal_text(clean, width, height)


def guard():
    if (os.environ.get("HERDR_SHARED_TEST_DISPOSABLE") != "1"
            or not pathlib.Path("/.dockerenv").exists()
            or sys.platform != "linux" or os.geteuid() != 0 or sys.flags.optimize):
        raise SystemExit("Refusing: requires explicitly opted-in disposable Linux root Docker container, without Python optimization")


def number(value):
    # Bincode standard unsigned varints, fixed by the published generation-1 codec.
    if value < 251:
        return bytes([value])
    if value <= 65535:
        return b"\xfb" + struct.pack("<H", value)
    return b"\xfc" + struct.pack("<I", value)


def string(value):
    data = value.encode()
    return number(len(data)) + data


def decode_number(data, offset):
    head = data[offset]
    if head < 251:
        return head, offset + 1
    length, form = {251: (2, "<H"), 252: (4, "<I"), 253: (8, "<Q")}[head]
    return struct.unpack_from(form, data, offset + 1)[0], offset + 1 + length


def decode_string(data, offset):
    length, offset = decode_number(data, offset)
    return data[offset:offset + length].decode(), offset + length


def write_frame(connection, payload):
    connection.sendall(struct.pack("<I", len(payload)) + payload)


def read_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        block = connection.recv(length - len(result))
        if not block:
            raise EOFError("native endpoint disconnected")
        result.extend(block)
    return bytes(result)


def read_frame(connection):
    length = struct.unpack("<I", read_exact(connection, 4))[0]
    assert length <= 16 * 1024 * 1024, "oversized native test frame"
    return read_exact(connection, length)


def native_probe(uid, requests, *, negotiate=True):
    """Speak real native frames under a real OS UID; return only decoded test data."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            fixture.identity(uid)()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect(str(pathlib.Path(fixture.SHARED).with_name("native")))
                hello = dict(generation=1, cell_width_px=8, cell_height_px=16,
                             surface_size=dict(cols=WIDTH, rows=HEIGHT), pixel_mouse=False,
                             direct_graphics=False, endpoint_keybindings=False, mouse_capture=False,
                             surface_active=True, shared_access=negotiate,
                             snapshot_codecs=["shell.snapshot.v1"], surface_codecs=["shell.surface.v1"],
                             input_codecs=["shell.input.semantic.v1"], blob_codecs=["shell.blob.v1"])
                write_frame(connection, number(20) + string("endpoint.hello.v1") + string(json.dumps(hello)))
                controls, wire = {}, bytearray()
                while "shell.snapshot.v1" not in controls:
                    frame = read_frame(connection)
                    wire.extend(frame)
                    tag, offset = decode_number(frame, 0)
                    if tag != 20:
                        continue
                    kind, offset = decode_string(frame, offset)
                    data, _ = decode_string(frame, offset)
                    controls[kind] = json.loads(data)
                    if kind == "endpoint.welcome.v1" and controls[kind].get("error"):
                        break
                responses = []
                if "shell.snapshot.v1" in controls:
                    boot = controls["shell.snapshot.v1"]["boot_id"]
                    for index, (method, params) in enumerate(requests):
                        request_id = f"native-probe-{index}"
                        body = json.dumps(dict(id=request_id, method=method, params=params))
                        write_frame(connection, number(15) + string(boot) + string(body))
                        chunks = bytearray()
                        while True:
                            frame = read_frame(connection)
                            wire.extend(frame)
                            tag, offset = decode_number(frame, 0)
                            if tag != 18:
                                continue
                            _, offset = decode_string(frame, offset)
                            response_id, offset = decode_string(frame, offset)
                            final = frame[offset]
                            length, offset = decode_number(frame, offset + 1)
                            if response_id == request_id:
                                chunks.extend(frame[offset:offset + length])
                                if final:
                                    responses.append(json.loads(chunks))
                                    break
                output = dict(controls=controls, responses=responses,
                              wire=wire.decode(errors="replace"))
        except Exception as error:
            output = dict(failure=repr(error))
        encoded = json.dumps(output).encode()
        while encoded:
            sent = os.write(write_fd, encoded)
            encoded = encoded[sent:]
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    chunks = bytearray()
    while block := os.read(read_fd, 65536):
        chunks.extend(block)
    os.close(read_fd)
    os.waitpid(pid, 0)
    value = json.loads(chunks)
    assert "failure" not in value, value
    return value


class Screen:
    def __init__(self, uid, *arguments, width=WIDTH, height=HEIGHT):
        self.data, self.closed = bytearray(), False
        self.width, self.height = width, height
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            fixture.identity(uid)()
            os.execve(fixture.BIN, [fixture.BIN, "--session", fixture.SESSION, *arguments], fixture.env(uid))
        self.resize(width, height)

    def resize(self, width, height):
        self.width, self.height = width, height
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

    def drain(self, seconds=.2):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not self.closed:
            ready, _, _ = select.select([self.master], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                chunk = os.read(self.master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    self.closed = True
                    break
                raise
            if not chunk:
                self.closed = True
                break
            self.data.extend(chunk)
        return self.text()

    def text(self):
        return terminal_text(self.data, self.width, self.height)

    def wait(self, text, seconds=15):
        deadline = time.monotonic() + seconds
        while text not in self.text():
            assert time.monotonic() < deadline and not self.closed, ("missing native TUI text", text, self.text(), self.data[-1200:])
            self.drain(.1)
        return self.text()

    def send(self, data):
        os.write(self.master, data)
        return self.drain(.2)

    def click(self, text):
        visible = self.text().splitlines()
        row = next((i for i, line in enumerate(visible) if text in line), None)
        assert row is not None, ("mouse target missing", text, self.text())
        column = visible[row].index(text) + min(2, len(text) - 1)
        # SGR cell mouse down/up: native client routes this through its real hit test.
        self.send(f"\x1b[<0;{column + 1};{row + 1}M\x1b[<0;{column + 1};{row + 1}m".encode())

    def close(self):
        if self.master < 0:
            return
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while True:
            try:
                done, _ = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                break
            if done:
                break
            if time.monotonic() >= deadline:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
                break
            self.drain(.05)
        os.close(self.master)
        self.master = -1


def main():
    guard()
    fixture.setup()
    fixture.SESSION = f"native-qualification-{os.getpid()}"
    fixture.SHARED = f"/tmp/herdr-share-{fixture.OWNER}-{fixture.SESSION}/socket"
    fixture.PRIVATE = f"/home/owner/.config/herdr-dev/sessions/{fixture.SESSION}/herdr.sock"
    config = pathlib.Path(f"/tmp/{fixture.SESSION}.toml")
    config.write_text('onboarding = false\n[keys]\nsplit_vertical = "ctrl+g"\nnext_workspace = "ctrl+n"\nprevious_workspace = "ctrl+p"\n[update]\nversion_check = false\nmanifest_check = false\n')
    os.environ["HERDR_CONFIG_PATH"] = str(config)
    checks, screens = [], []

    def check(ok, label):
        assert ok, label
        checks.append(label)
        print("PASS", label, flush=True)

    def owner_rpc(method, params=None):
        return fixture.result(fixture.OWNER, method, params, private=True)

    def snapshot():
        return owner_rpc("session.snapshot")["snapshot"]

    def read(pane):
        return owner_rpc("pane.read", dict(pane_id=pane, source="recent", format="text"))["read"]["text"]

    def shared_screen(uid, **options):
        screen = Screen(uid, "session", "attach", "--shared-owner", "owner", "--shared-session", fixture.SESSION, **options)
        screens.append(screen)
        return screen

    def grant(user, workspace, role):
        fixture.cli(fixture.OWNER, "--session", fixture.SESSION, "session", "access", "--user", user,
                    "--space", workspace, "--role", role, "--ack-owner-execution")

    log_path = pathlib.Path(f"/tmp/{fixture.SESSION}.log")
    with log_path.open("w") as log:
        server = subprocess.Popen([fixture.BIN, "--session", fixture.SESSION, "server"],
                preexec_fn=fixture.identity(fixture.OWNER), env=fixture.env(fixture.OWNER), stdout=log, stderr=log)
        try:
            fixture.wait(fixture.PRIVATE)
            for label in ("NATIVE_ALICE", "NATIVE_BOB_SECRET", "NATIVE_VIEW"):
                owner_rpc("workspace.create", dict(label=label, cwd="/home/owner"))
            state = snapshot()
            workspaces = {w["label"]: w["workspace_id"] for w in state["workspaces"]}
            panes = {wid: next(p["pane_id"] for p in state["panes"] if p["workspace_id"] == wid) for wid in workspaces.values()}
            alice, bob, view = (workspaces[name] for name in ("NATIVE_ALICE", "NATIVE_BOB_SECRET", "NATIVE_VIEW"))
            for wid, marker in ((alice, "NATIVE_ALICE_OUTPUT"), (bob, "BOB_TERMINAL_SECRET"), (view, "NATIVE_VIEW_OUTPUT")):
                owner_rpc("pane.send_text", dict(pane_id=panes[wid], text=f"printf '{marker}\\n'\n"))
            fixture.cli(fixture.OWNER, "--session", fixture.SESSION, "session", "share", "enable", "--group", "herdr-test")
            fixture.wait(str(pathlib.Path(fixture.SHARED).with_name("native")))
            empty = native_probe(1002, [])
            check(empty["controls"]["shared.access.v1"]["workspaces"] == {}
                  and not empty["controls"]["shell.snapshot.v1"]["workspaces"],
                  "new native OS user receives an empty snapshot before any grants")
            grant("alice", alice, "control")
            grant("alice", view, "view")
            grant("bob", view, "view")
            view_tab=next(t["tab_id"] for t in state["tabs"] if t["workspace_id"]==view)
            denied_calls=[("pane.focus",dict(pane_id=panes[view])),
                          ("pane.focus_direction",dict(pane_id=panes[view],direction="left")),
                          ("pane.scroll",dict(pane_id=panes[view],offset_from_bottom=1)),
                          ("pane.rename",dict(pane_id=panes[view],label="MUST_NOT_RENAME")),
                          ("tab.rename",dict(tab_id=view_tab,label="MUST_NOT_RENAME")),
                          ("tab.create",dict(workspace_id=view,cwd="/home/owner")),
                          ("workspace.rename",dict(workspace_id=view,label="MUST_NOT_RENAME")),
                          ("workspace.create",dict(label="MUST_NOT_CREATE",cwd="/home/owner")),
                          ("server.stop",{}),("server.reload_config",{}),("future.unclassified.v999",{})]
            direct_view=native_probe(1002,denied_calls)
            check(len(direct_view.get("responses",[]))==len(denied_calls)
                  and all("error" in response for response in direct_view["responses"]),
                  "untrusted native View client cannot bypass UI guards through viewport mutations, global operations or unknown methods")
            check("MUST_NOT" not in json.dumps(snapshot()) and server.poll() is None,
                  "denied native method matrix leaves owner runtime and workspace metadata unchanged")
            check(os.stat(pathlib.Path(fixture.SHARED).with_name("native")).st_mode & 0o777 == 0o660,
                  "native shared endpoint retains the OS group socket boundary")
            rejected = native_probe(1001, [], negotiate=False)
            check(rejected["controls"]["endpoint.welcome.v1"]["error"]["code"] == "shared_access_required",
                  "native shared endpoint rejects a generation-1 client without shared-access negotiation")
            probe = native_probe(1001, [("workspace.focus", dict(workspace_id=alice)),
                                       ("workspace.focus", dict(workspace_id=bob)), ("workspace.focus", dict(workspace_id="w_nonexistent")),
                                       ("workspace.create", dict(label="MUST_NOT_CREATE")),
                                       ("pane.split", dict(target_pane_id=panes[view], direction="right"))])
            check("shared_access.v1" in probe["controls"]["endpoint.welcome.v1"]["capabilities"],
                  "native shared welcome explicitly advertises negotiated permissions")
            access = probe["controls"]["shared.access.v1"]
            check(access["caller_uid"] == 1001 and access["workspaces"] == {alice: "control", view: "view"},
                  "native companion preserves kernel caller identity and exact per-space roles")
            check("NATIVE_BOB_SECRET" not in probe["wire"] and bob not in probe["wire"] and panes[bob] not in probe["wire"],
                  "native wire snapshots exclude hidden space labels and object IDs")
            assert "result" in probe["responses"][0], probe["responses"][0]
            check(True, "native endpoint API navigates an authorized space")
            errors = [response.get("error") for response in probe["responses"][1:]]
            check(all(error and error.get("code") == "unavailable" for error in errors) and errors[0] == errors[1],
                  "guessed hidden/nonexistent native objects and global/View mutations are denied")
            owner = Screen(fixture.OWNER)
            screens.append(owner)
            owner.wait("NATIVE_BOB_SECRET")
            check("NATIVE_ALICE" in owner.text() and "NATIVE_VIEW" in owner.text(),
                  "owner's original native screen still lists every space")
            owner.close()
            screen = shared_screen(1001)
            screen.wait("NATIVE_ALICE_OUTPUT")
            check("NATIVE_ALICE" in screen.text() and "NATIVE_VIEW" in screen.text()
                  and "NATIVE_BOB_SECRET" not in screen.data.decode(errors="replace")
                  and "BOB_TERMINAL_SECRET" not in screen.data.decode(errors="replace"),
                  "real native participant TUI renders full allowed sidebar and terminal without hidden sentinels")
            live = fixture.result(fixture.OWNER, "users")["connected"]
            check([connection["uid"] for connection in live] == [1001],
                  "owner administration reports the real connected native OS account")
            screen.send(b"printf NATIVE_; printf INPUT_EXECUTED; printf '\\n'\r")
            screen.wait("NATIVE_INPUT_EXECUTED")
            check(True, "native Control keyboard input executes in the existing terminal")
            before = len([p for p in snapshot()["panes"] if p["workspace_id"] == alice])
            screen.send(b"\x07")
            deadline = time.monotonic() + 8
            while len([p for p in snapshot()["panes"] if p["workspace_id"] == alice]) == before:
                assert time.monotonic() < deadline, ("native split did not execute", screen.drain(.1))
                screen.drain(.1)
            check(True, "native Control split shortcut creates a pane inside its granted space")
            screen.click("NATIVE_VIEW")
            screen.wait("NATIVE_VIEW_OUTPUT")
            check(True, "native mouse sidebar navigation switches to a permitted View space")
            screen.send(b"\x10")  # Custom previous_workspace = Ctrl+p, native keybinding path.
            screen.send(b"printf NATIVE_; printf NAV_EXECUTED; printf '\\n'\r")
            screen.wait("NATIVE_NAV_EXECUTED")
            check(any("NATIVE_NAV_EXECUTED" in read(p["pane_id"]) for p in snapshot()["panes"] if p["workspace_id"] == alice),
                  "native keyboard workspace navigation returns to the granted Control terminal")
            screen.click("NATIVE_VIEW")
            screen.wait("NATIVE_VIEW_OUTPUT")
            screen.send(b"printf VIEW_; printf MUST_NOT_EXECUTE; printf '\\n'\r")
            screen.drain(.5)
            check("VIEW_MUST_NOT_EXECUTE" not in read(panes[view]), "native View keyboard input cannot execute terminal commands")
            before_view = len([p for p in snapshot()["panes"] if p["workspace_id"] == view])
            screen.send(b"\x07")
            screen.drain(.5)
            check(len([p for p in snapshot()["panes"] if p["workspace_id"] == view]) == before_view,
                  "native View split shortcut cannot mutate the shared space")
            screen.close()
            viewer = shared_screen(1002, width=52, height=12)
            viewer.wait("NATIVE_VIEW_OUTPUT")
            geometry_before = owner_rpc("pane.layout", dict(pane_id=panes[view]))
            viewer.resize(30, 10)
            viewer.drain(.7)
            geometry_after = owner_rpc("pane.layout", dict(pane_id=panes[view]))
            check(geometry_before["layout"]["area"] == geometry_after["layout"]["area"], "View client resizing leaves authoritative PTY geometry unchanged")
            viewer.close()
            screen = shared_screen(1001)
            screen.wait("NATIVE_ALICE")
            grant("alice", alice, "none")
            deadline = time.monotonic() + 8
            while not screen.closed and time.monotonic() < deadline:
                screen.drain(.1)
            check(screen.closed and "shared session disconnected" in screen.data.decode(errors="replace").lower(),
                  "grant revocation disconnects the existing native client with an explicit notice")
            check("NATIVE_ALICE" not in screen.text() and "NATIVE_ALICE_OUTPUT" not in screen.text(),
                  "native disconnect clears the old space and terminal surface from the screen")
            screen.close()
            check(fixture.result(fixture.OWNER, "users")["connected"] == [],
                  "owner administration removes the revoked native connection immediately")
            refreshed = native_probe(1001, [])
            check(refreshed["controls"]["shared.access.v1"]["workspaces"] == {view: "view"}
                  and "NATIVE_ALICE" not in refreshed["wire"],
                  "reconnected native client receives only remaining grants")
            saved_grants=fixture.result(fixture.OWNER,"grants.get")["grants"]
            fixture.cli(fixture.OWNER,"--session",fixture.SESSION,"server","stop")
            server.wait(timeout=10)
            check("error" in fixture.request(1001,"spaces"),"stopped native daemon leaves its old broker fail closed")
            server=subprocess.Popen([fixture.BIN,"--session",fixture.SESSION,"server"],preexec_fn=fixture.identity(fixture.OWNER),env=fixture.env(fixture.OWNER),stdout=log,stderr=log)
            fixture.wait(fixture.PRIVATE)
            check("error" in fixture.request(1001,"spaces"),"old broker cannot attach its grants to an unverified replacement daemon")
            fixture.cli(fixture.OWNER,"--session",fixture.SESSION,"session","share","disable")
            fixture.cli(fixture.OWNER,"--session",fixture.SESSION,"session","share","enable","--group","herdr-test")
            check(fixture.result(fixture.OWNER,"grants.get")["grants"]==saved_grants,"native daemon restart preserves durable account and incarnation grant bindings")
            restarted=native_probe(1001,[])
            check(restarted["controls"]["shared.access.v1"]["workspaces"]=={view:"view"}
                  and "NATIVE_ALICE" not in restarted["wire"],"full native attachment restores only the remaining durable grant after restart")
            owner_rpc("pane.send_text",dict(pane_id=panes[view],text="printf ACCOUNT_; printf DEPROVISION_OUTPUT; printf '\\n'\n"))
            account_screen=shared_screen(1001)
            account_screen.wait("ACCOUNT_DEPROVISION_OUTPUT")
            renamed=False
            try:
                # --prefix models an NSS/account-store change while the old UID
                # still owns a client process. Ordinary usermod's process-busy
                # guard would otherwise prohibit this deprovisioning fixture.
                # main()'s disposable-root guard runs before this mutation.
                subprocess.run(["usermod","--prefix","/","--login","alice-renamed","alice"],check=True)
                renamed=True
                deadline=time.monotonic()+15
                while not account_screen.closed and time.monotonic()<deadline:
                    account_screen.drain(.1)
                check(account_screen.closed and "shared session disconnected" in account_screen.data.decode(errors="replace").lower(),
                      "OS account rename disconnects its existing native client within the refresh bound")
                check("ACCOUNT_DEPROVISION_OUTPUT" not in account_screen.text(),
                      "account invalidation clears previously visible native terminal content")
                grants_after_rename=fixture.result(fixture.OWNER,"grants.get")["grants"]
                check(not any(g["uid"]==1001 for g in grants_after_rename),
                      "changed OS account identity permanently prunes the old UID/account grants")
            finally:
                account_screen.close()
                if renamed:
                    subprocess.run(["usermod","--prefix","/","--login","alice","alice-renamed"],check=True)
            returning=native_probe(1001,[])
            check(returning["controls"]["shared.access.v1"]["workspaces"]=={}
                  and not any(g["uid"]==1001 for g in fixture.result(fixture.OWNER,"grants.get")["grants"]),
                  "restoring the OS account name does not resurrect pruned grants")
            fixture.cli(fixture.OWNER, "--session", fixture.SESSION, "session", "share", "disable")
            check(not pathlib.Path(fixture.SHARED).with_name("native").exists() and server.poll() is None,
                  "sharing disable removes native listener while the owner runtime keeps running")
            print(json.dumps(dict(passed=len(checks), checks=checks), indent=2))
        finally:
            for screen in screens:
                screen.close()
            try:
                fixture.cli(fixture.OWNER, "--session", fixture.SESSION, "session", "share", "disable")
            except Exception:
                pass
            try:
                fixture.cli(fixture.OWNER, "--session", fixture.SESSION, "server", "stop")
            except Exception:
                server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            config.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
