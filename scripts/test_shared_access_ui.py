#!/usr/bin/env python3
"""Exercise the real shared-access screens in a disposable Linux container.

Requires a built binary, root only inside Docker, and provisioned owner/alice/bob
accounts in herdr-test. Never creates or changes host accounts. Uses a unique
named native session and cleans up only processes it starts.
"""
import argparse
import errno
import fcntl
import json
import os
import pathlib
import pty
import pwd
import re
import select
import socket
import struct
import subprocess
import termios
import time
import unicodedata


def terminal_text(data, width=180, height=40):
    """Replay cursor addressing used by Crossterm; no external emulator needed."""
    grid = [[" "] * width for _ in range(height)]
    row = column = 0
    text = data.decode("utf-8", errors="replace")
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\x1b":
            match = re.match(r"\x1b\[([0-?]*)([ -/]*)([@-~])", text[index:])
            if match:
                parameters, _, command = match.groups()
                numbers = [int(value) if value.isdigit() else 0 for value in parameters.split(";")]
                first = numbers[0] if numbers else 0
                if command in "Hf":
                    row = max(0, (first or 1) - 1)
                    column = max(0, (numbers[1] if len(numbers) > 1 and numbers[1] else 1) - 1)
                elif command == "G": column = max(0, (first or 1) - 1)
                elif command == "d": row = max(0, (first or 1) - 1)
                elif command == "A": row = max(0, row - (first or 1))
                elif command == "B": row = min(height - 1, row + (first or 1))
                elif command == "C": column = min(width - 1, column + (first or 1))
                elif command == "D": column = max(0, column - (first or 1))
                elif command == "J" and first in (2, 3): grid = [[" "] * width for _ in range(height)]
                elif command == "K" and row < height:
                    start, end = (0, width) if first == 2 else ((0, column + 1) if first == 1 else (column, width))
                    grid[row][start:end] = [" "] * max(0, end - start)
                index += len(match.group())
                continue
            osc = re.match(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", text[index:])
            index += len(osc.group()) if osc else 2
            continue
        if char == "\r": column = 0
        elif char == "\n": row = min(height - 1, row + 1)
        elif char == "\b": column = max(0, column - 1)
        elif char >= " " and not unicodedata.combining(char):
            if row < height and column < width: grid[row][column] = char
            column += 2 if unicodedata.east_asian_width(char) in "WF" else 1
        index += 1
    return "\n".join("".join(line) for line in grid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="/target/debug/herdr")
    options = parser.parse_args()
    assert pathlib.Path("/.dockerenv").exists() and os.geteuid() == 0, (
        "Run only inside an explicitly provisioned disposable root Docker container"
    )
    accounts = {name: pwd.getpwnam(name) for name in ("owner", "alice", "bob")}
    owner = accounts["owner"].pw_uid
    session = f"ui-qualification-{os.getpid()}"
    shared = f"/tmp/herdr-share-{owner}-{session}/socket"
    private = f"{accounts['owner'].pw_dir}/.config/herdr-dev/sessions/{session}/herdr.sock"
    checks = []
    active_screens = []

    def check(condition, label):
        assert condition, label
        checks.append(label)
        print("PASS", label, flush=True)

    def change_user(name):
        account = accounts[name]

        def change():
            os.initgroups(name, account.pw_gid)
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
            os.chdir(account.pw_dir)

        return change

    def environment(name):
        account = accounts[name]
        clean = {key: value for key, value in os.environ.items() if not key.startswith("HERDR_")}
        return dict(clean, HOME=account.pw_dir, USER=name, LOGNAME=name,
                    SHELL="/bin/bash", TERM="xterm-256color")

    def cli(name, *args):
        completed = subprocess.run([options.binary, "--session", session, *args],
                                   preexec_fn=change_user(name), env=environment(name),
                                   capture_output=True, text=True, timeout=20)
        assert completed.returncode == 0, (args, completed.stdout, completed.stderr)
        return completed.stdout

    def rpc(method, params=None, native=False):
        # Parent runs as container root. Fork and drop credentials before opening
        # the socket so the daemon observes the actual owner peer UID.
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                change_user("owner")()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(10)
                    connection.connect(private if native else shared)
                    connection.sendall(json.dumps(dict(id="ui-test", method=method, params=params or {})).encode() + b"\n")
                    data = connection.makefile("rb").readline(4 * 1024 * 1024)
                    os.write(write_fd, data)
            except Exception as error:
                os.write(write_fd, json.dumps(dict(error=str(error))).encode())
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        data = bytearray()
        while chunk := os.read(read_fd, 65536):
            data.extend(chunk)
        os.close(read_fd)
        os.waitpid(pid, 0)
        result = json.loads(data)
        assert "result" in result, (method, result)
        return result["result"]

    class Screen:
        def __init__(self, name, *arguments):
            self.pid, self.master = pty.fork()
            self.data = bytearray()
            self.closed = False
            if self.pid == 0:
                change_user(name)()
                os.execve(options.binary, [options.binary, "--session", session, *arguments], environment(name))
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 180, 0, 0))
            active_screens.append(self)

        def drain(self, seconds=.2):
            deadline = time.monotonic() + seconds
            new = bytearray()
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
                new.extend(chunk)
            return new.decode("utf-8", errors="replace")

        def wait(self, text, seconds=8):
            deadline = time.monotonic() + seconds
            while text not in terminal_text(self.data):
                assert time.monotonic() < deadline, ("missing screen text", text, terminal_text(self.data))
                self.drain(.1)

        def send(self, data):
            os.write(self.master, data)
            return self.drain(.15)

        def close(self):
            if not self.closed:
                self.send(b"\x11")  # Ctrl+q always exits both screens.
                self.drain(.2)
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
            os.close(self.master)
            self.master = -1

    def admin_alice():
        screen = Screen("owner", "session", "access")
        screen.wait("Space access")
        screen.wait("OS accounts")
        screen.wait("Space permissions")
        screen.send(b"/alice\r")
        screen.send(b"\t")
        return screen

    log_path = f"/tmp/herdr-{session}.log"
    with open(log_path, "w") as log:
        server = subprocess.Popen([options.binary, "--session", session, "server"],
                                  preexec_fn=change_user("owner"), env=environment("owner"),
                                  stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while not os.path.exists(private):
                assert server.poll() is None, pathlib.Path(log_path).read_text()
                assert time.monotonic() < deadline, "native server did not start"
                time.sleep(.05)
            for label in ("ALICE_UI_ALLOWED", "BOB_UI_FORBIDDEN", "SHARED_UI_VIEW"):
                rpc("workspace.create", dict(label=label, cwd=accounts["owner"].pw_dir), native=True)
            state = rpc("session.snapshot", native=True)["snapshot"]
            first = state["workspaces"][0]["workspace_id"]
            pane = next(p["pane_id"] for p in state["panes"] if p["workspace_id"] == first)
            cli("owner", "session", "share", "enable", "--group", "herdr-test")

            screen = admin_alice()
            check("ALICE_UI_ALLOWED" in screen.data.decode(errors="replace"), "admin displays OS users and space matrix in a real PTY")
            screen.send(b" ")
            screen.wait("view")
            screen.send(b"q")
            screen.close()
            check(rpc("grants.get")["grants"] == [], "cancel discards drafted View grant")

            screen = admin_alice()
            screen.send(b" ")
            screen.send(b" ")
            screen.wait("Grant Control?")
            check("files and credentials" in terminal_text(screen.data), "Control acknowledgement explains owner privileges")
            screen.send(b"n")
            screen.send(b"s")
            screen.close()
            grants = rpc("grants.get")["grants"]
            check(len(grants) == 1 and grants[0]["role"] == "view", "declining Control saves only View")

            screen = admin_alice()
            screen.send(b" ")
            screen.wait("Grant Control?")
            screen.send(b"y")
            screen.send(b"s")
            screen.close()
            grants = rpc("grants.get")["grants"]
            check(len(grants) == 1 and grants[0]["role"] == "control", "acknowledged Control saves through the administration screen")

            rpc("pane.send_text", dict(pane_id=pane, text="printf 'UI_OUTPUT_SENTINEL\\n'\n"), native=True)
            alice = Screen("alice", "session", "attach", "--text", "--shared-owner", "owner", "--shared-session", session)
            alice.wait("UI_OUTPUT_SENTINEL")
            raw = alice.data.decode(errors="replace")
            check("ALICE_UI_ALLOWED" in raw and "BOB_UI_FORBIDDEN" not in raw
                  and "Herdr shared · alice" in terminal_text(alice.data),
                  "participant PTY renders own identity, allowed space and output without forbidden space")
            # The marker is split across commands, so an echoed input line does
            # not satisfy this assertion without execution in the real shell.
            alice.send(b"printf UI_; printf TYPED; printf '\\n'\r")
            alice.wait("UI_TYPED")
            check(True, "participant keyboard input reaches its controlled terminal")
            bob = Screen("bob", "session", "attach", "--text", "--shared-owner", "owner", "--shared-session", session)
            bob.wait("No spaces have been shared")
            check("ALICE_UI_ALLOWED" not in bob.data.decode(errors="replace"), "ungranted participant PTY displays empty state")
            bob.close()

            screen = admin_alice()
            screen.send(b"r")
            screen.wait("All grants for this user removed")
            screen.send(b"s")
            screen.close()
            check(rpc("grants.get")["grants"] == [], "revoke-user screen action persists removal of all grants")
            alice.wait("No spaces have been shared")
            visible = terminal_text(alice.data)
            check("UI_OUTPUT_SENTINEL" not in visible and "ALICE_UI_ALLOWED" not in visible,
                  "live participant clears output and shows empty state after revocation")
            alice.close()

            # Supporting broker-projection scaling evidence, not a substitute
            # for native retained-render 1/15-pane release qualification.
            while len(state["workspaces"]) < 15:
                rpc("workspace.create", dict(label=f"SCALE_{len(state['workspaces'])}", cwd=accounts["owner"].pw_dir), native=True)
                state = rpc("session.snapshot", native=True)["snapshot"]
            timings = {}
            for cardinality in (1, 15):
                current = rpc("grants.get")
                grants = [dict(uid=accounts["alice"].pw_uid, account_name="alice", workspace_id=w["workspace_id"], role="view")
                          for w in state["workspaces"][:cardinality]]
                rpc("grants.set", dict(expected_revision=current["revision"], grants=grants, acknowledge_owner_execution=False))
                samples = []
                for _ in range(3):
                    started = time.perf_counter()
                    output = cli("alice", "session", "attach", "--shared-owner", "owner", "--shared-session", session, "--json")
                    samples.append((time.perf_counter() - started) * 1000)
                    check(len(json.loads(output)["workspaces"]) == cardinality,
                          f"projection membership correct at {cardinality} spaces ({len(samples)}/3)")
                timings[str(cardinality)] = dict(samples_ms=[round(value, 2) for value in samples], mean_ms=round(sum(samples) / len(samples), 2))

            screen = Screen("owner", "session", "access")
            screen.wait("Space access")
            screen.send(b"d")
            screen.wait("Disable sharing for all participants?")
            screen.send(b"n")
            check(rpc("status")["shared"], "declining disable leaves sharing active")
            screen.send(b"d")
            screen.send(b"y")
            screen.close()
            deadline = time.monotonic() + 3
            while os.path.exists(shared) and time.monotonic() < deadline:
                time.sleep(.02)
            check(not os.path.exists(shared) and server.poll() is None,
                  "confirmed disable removes shared socket while native terminals keep running")
            print(json.dumps(dict(passed=len(checks), checks=checks, projection_scaling=timings), indent=2))
        finally:
            for screen in active_screens:
                if screen.master >= 0:
                    try:
                        if not screen.closed:
                            os.kill(screen.pid, 15)
                        os.close(screen.master)
                    except (ProcessLookupError, OSError):
                        pass
            try:
                cli("owner", "session", "share", "disable")
            except Exception:
                pass
            try:
                cli("owner", "server", "stop")
            except Exception:
                server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
