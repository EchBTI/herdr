#!/usr/bin/env python3
"""Opt-in multi-UID shared-access qualification in a disposable root container.

Run with scripts/shared-access-test.Dockerfile. This creates fixture OS users
and modifies /etc/machine-id inside the explicitly opted-in container. Never
run with host account/config directories mounted. No credentials are required.
Optional HERDR_SHARED_OLD_BINARY supplies a real older debug binary; that
compatibility scenario is explicitly reported as skipped when absent.
"""
import grp, json, os, pwd, socket, subprocess, sys, time, pathlib


BIN=os.environ.get('HERDR_SHARED_TEST_BINARY','/target/debug/herdr')
SESSION=f'shared-qualification-{os.getpid()}'
OWNER=1000
GROUP=2000
SHARED=f'/tmp/herdr-share-{OWNER}-{SESSION}/socket'
PRIVATE=f'/home/owner/.config/herdr-dev/sessions/{SESSION}/herdr.sock'
RESULTS=[]
SKIPPED=[]

def check(ok, label):
    assert ok, label
    RESULTS.append(label)
    print('PASS',label,flush=True)

def identity(uid):
    account=pwd.getpwuid(uid)
    def setup():
        os.initgroups(account.pw_name,account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(uid)
        os.chdir(account.pw_dir)
    return setup

def env(uid):
    account=pwd.getpwuid(uid)
    return dict(os.environ,HOME=account.pw_dir,USER=account.pw_name,LOGNAME=account.pw_name,SHELL='/bin/bash',TERM='xterm-256color')

def cli(uid,*args):
    result=subprocess.run([BIN,*args],preexec_fn=identity(uid),env=env(uid),capture_output=True,text=True,timeout=15)
    assert result.returncode==0,(args,result.returncode,result.stdout,result.stderr)
    return result.stdout

def request(uid,method,params=None,private=False,extras=None,socket_path=None):
    body=dict(id='qualification',method=method,params=params or {})
    body.update(extras or {})
    read_fd,write_fd=os.pipe()
    pid=os.fork()
    if pid==0:
        os.close(read_fd)
        try:
            identity(uid)()
            connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            connection.settimeout(10)
            connection.connect(socket_path or (PRIVATE if private else SHARED))
            connection.sendall(json.dumps(body).encode()+b'\n')
            raw=connection.makefile('rb').readline(4*1024*1024)
            os.write(write_fd,raw)
        except Exception as exc:
            os.write(write_fd,json.dumps(dict(transport_error=str(exc))).encode())
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    chunks=[]
    while True:
        chunk=os.read(read_fd,65536)
        if not chunk:break
        chunks.append(chunk)
    os.close(read_fd)
    os.waitpid(pid,0)
    raw=b''.join(chunks)
    return json.loads(raw) if raw else dict(error='closed without data')

def result(uid,method,params=None,private=False):
    value=request(uid,method,params,private)
    assert 'result' in value,(method,value)
    return value['result']

def wait(path):
    for _ in range(200):
        if os.path.exists(path): return
        time.sleep(.05)
    raise AssertionError('endpoint missing '+path)

def setup():
    # Fixture accounts are created only after main's disposable-container guard.
    try:
        group=grp.getgrnam('herdr-test')
        if group.gr_gid!=GROUP:raise RuntimeError('existing fixture group has unexpected GID')
    except KeyError:
        subprocess.run(['groupadd','-g',str(GROUP),'herdr-test'],check=True)
    for name,uid in [('owner',1000),('alice',1001),('bob',1002)]:
        try:
            account=pwd.getpwnam(name)
        except KeyError:
            subprocess.run(['useradd','-m','-u',str(uid),'-s','/bin/bash','-G','herdr-test',name],check=True)
            account=pwd.getpwnam(name)
        if account.pw_uid!=uid or account.pw_dir!=f'/home/{name}':
            raise RuntimeError('existing fixture account has unexpected identity')
        if GROUP not in os.getgrouplist(name,account.pw_gid):
            raise RuntimeError('existing fixture account lacks test group; refusing to alter it')
    pathlib.Path('/etc/machine-id').write_text('f24d3d3ded65412b80c80e747d8879c1\n')


def qualify_old_native():
    """Optional actual older binary; never substitute a mock compatibility claim."""
    binary=os.environ.get('HERDR_SHARED_OLD_BINARY')
    if not binary:
        SKIPPED.append('old native binary compatibility: set HERDR_SHARED_OLD_BINARY to test a real baseline binary')
        return
    legacy_session=SESSION+'-legacy'
    legacy_socket=f'/home/owner/.config/herdr-dev/sessions/{legacy_session}/herdr.sock'
    with open('/tmp/'+legacy_session+'.log','w') as legacy_log:
        old=subprocess.Popen([binary,'--session',legacy_session,'server'],preexec_fn=identity(OWNER),env=env(OWNER),stdout=legacy_log,stderr=legacy_log)
        try:
            wait(legacy_socket)
            reply=request(OWNER,'shared.execute.v1',dict(request=dict(id='qualification',method='pane.send_text',params=dict(pane_id='not-a-pane',text='MUST_NOT_EXECUTE')),scope={}),socket_path=legacy_socket)
            check(reply.get('error',{}).get('code')=='invalid_request' and 'result' not in reply,'older native daemon rejects new scoped method instead of ignoring scope')
        finally:
            old.terminate()
            try:old.wait(timeout=10)
            except subprocess.TimeoutExpired:old.kill();old.wait()

def main():
    if (os.environ.get('HERDR_SHARED_TEST_DISPOSABLE')!='1'
            or not os.path.exists('/.dockerenv')
            or sys.platform!='linux'
            or os.geteuid()!=0
            or sys.flags.optimize):
        raise SystemExit('Refusing: requires HERDR_SHARED_TEST_DISPOSABLE=1 inside a disposable Linux Docker container running as root, without Python optimization.')
    setup()
    log=open('/tmp/'+SESSION+'-server.log','w')
    server=subprocess.Popen([BIN,'--session',SESSION,'server'],preexec_fn=identity(OWNER),env=env(OWNER),stdout=log,stderr=log)
    try:
        wait(PRIVATE)
        check(server.poll() is None,'native owner server starts')
        check(os.stat(PRIVATE).st_mode&0o777==0o600,'private native API socket stays 0600')
        for label in ['ALICE_SENTINEL_PRIVATE','BOB_SENTINEL_PRIVATE','SHARED_VIEW_SENTINEL']:
            result(OWNER,'workspace.create',dict(label=label,cwd='/home/owner'),private=True)
        snapshot=result(OWNER,'session.snapshot',private=True)['snapshot']
        workspaces={w['label']:w['workspace_id'] for w in snapshot['workspaces']}
        panes={w:next(p['pane_id'] for p in snapshot['panes'] if p['workspace_id']==w) for w in workspaces.values()}
        alice=workspaces['ALICE_SENTINEL_PRIVATE'];bob=workspaces['BOB_SENTINEL_PRIVATE'];shared=workspaces['SHARED_VIEW_SENTINEL']
        cli(OWNER,'--session',SESSION,'session','share','enable','--group','herdr-test')
        wait(SHARED)
        check(os.stat(SHARED).st_mode&0o777==0o660,'shared socket has 0660')
        check(os.stat(os.path.dirname(SHARED)).st_mode&0o777==0o750,'shared directory has 0750')
        check(result(1001,'spaces')['workspaces']==[],'new user receives empty state without spaces')
        for user,space,role in [('alice',alice,'control'),('bob',bob,'control'),('alice',shared,'view'),('bob',shared,'view')]:
            args=['--session',SESSION,'session','access','--user',user,'--space',space,'--role',role,'--ack-owner-execution']
            cli(OWNER,*args)
        for uid,own,forbidden in [(1001,'ALICE_SENTINEL_PRIVATE','BOB_SENTINEL_PRIVATE'),(1002,'BOB_SENTINEL_PRIVATE','ALICE_SENTINEL_PRIVATE')]:
            spaces=result(uid,'spaces')
            raw=json.dumps(spaces)
            check(own in raw and forbidden not in raw and 'SHARED_VIEW_SENTINEL' in raw,f'UID {uid} projection excludes forbidden sentinel')
        check('error' in request(1001,'grants.get'),'non-owner cannot administer grants')
        check('error' in request(1001,'users'),'non-owner cannot enumerate OS users')
        check('error' in request(1001,'spaces',extras={'uid':OWNER}),'spoofed outer UID rejected')
        check('error' in request(1001,'spaces',{'uid':OWNER}),'spoofed parameter UID rejected')
        check('error' in request(1001,'input',dict(pane_id=panes[shared],text='echo UNAUTHORIZED\n')),'View cannot send terminal input')
        denied_other=request(1001,'read',dict(pane_id=panes[bob]))
        denied_unknown=request(1001,'read',dict(pane_id='w999:t999:p999'))
        check(denied_other.get('error')==denied_unknown.get('error'),'guessed hidden and nonexistent pane IDs have identical errors')
        check('transport_error' in request(1001,'session.snapshot',private=True),'other OS user cannot connect private native socket')
        result(1001,'input',dict(pane_id=panes[alice],text="printf 'ALICE_%s\\n' 'OUTPUT_SENTINEL'\n"))
        for _ in range(50):
            text=result(1001,'read',dict(pane_id=panes[alice]))['text']
            if 'ALICE_OUTPUT_SENTINEL' in text:break
            time.sleep(.05)
        check('ALICE_OUTPUT_SENTINEL' in text,'Control sends input and reads actual PTY output')
        check('error' in request(1002,'read',dict(pane_id=panes[alice])),'Bob cannot read Alice terminal output')
        check('error' in request(1001,'close',dict(pane_id=panes[alice])),'Control cannot close the last pane and implicitly delete its space')
        before={p['pane_id'] for p in result(OWNER,'session.snapshot',private=True)['snapshot']['panes']}
        result(1001,'split',dict(pane_id=panes[alice],direction='right'))
        after=result(OWNER,'session.snapshot',private=True)['snapshot']['panes']
        created=next(p['pane_id'] for p in after if p['pane_id'] not in before)
        check(any(p['pane_id']==created and p['workspace_id']==alice for p in after),'Control can split within its granted space')
        result(1001,'close',dict(pane_id=created))
        check('result' in request(1001,'read',dict(pane_id=panes[alice])),'Control can close an extra pane while retaining its space')
        result(OWNER,'workspace.rename',dict(workspace_id=alice,label='ALICE_RENAMED_SENTINEL'),private=True)
        check('ALICE_RENAMED_SENTINEL' in json.dumps(result(1001,'spaces')),'owner rename preserves the stable space grant')
        result(OWNER,'workspace.close',dict(workspace_id=bob),private=True)
        result(OWNER,'workspace.create',dict(label='BOB_SENTINEL_PRIVATE',cwd='/home/owner'),private=True)
        check('BOB_SENTINEL_PRIVATE' not in json.dumps(result(1002,'spaces')),'delete then recreate same label never resurrects grants')
        cli(OWNER,'--session',SESSION,'session','access','--user','alice','--space',alice,'--role','none','--ack-owner-execution')
        check(alice not in [w['id'] for w in result(1001,'spaces')['workspaces']],'revocation removes space immediately')
        check('error' in request(1001,'read',dict(pane_id=panes[alice])),'revocation denies subsequent reads')
        check('error' in request(1001,'input',dict(pane_id=panes[alice],text='echo REVOKED\n')),'revocation denies subsequent input')
        cli(OWNER,'--session',SESSION,'session','share','disable')
        for _ in range(50):
            if not os.path.exists(SHARED):break
            time.sleep(.02)
        check(not os.path.exists(SHARED),'sharing disable removes listener')
        check(server.poll() is None,'sharing disable leaves native session running')
        cli(OWNER,'--session',SESSION,'session','share','enable','--group','herdr-test')
        check('SHARED_VIEW_SENTINEL' in json.dumps(result(1001,'spaces')),'broker disable and re-enable preserves grants for the same native runtime')
        audit_files=list(pathlib.Path('/home/owner/.config/herdr-dev/sessions/'+SESSION+'/shared-access').rglob('access-audit.jsonl'))
        check(bool(audit_files) and all(p.stat().st_uid==OWNER and p.stat().st_mode&0o777==0o600 and p.stat().st_size<=1024*1024 for p in audit_files),'audit log is bounded and owner-only 0600')
        cli(OWNER,'--session',SESSION,'server','stop')
        server.wait(timeout=10)
        check('error' in request(1001,'spaces'),'old broker denies access after native daemon stops')
        server=subprocess.Popen([BIN,'--session',SESSION,'server'],preexec_fn=identity(OWNER),env=env(OWNER),stdout=log,stderr=log)
        wait(PRIVATE)
        check('error' in request(1001,'spaces'),'old broker denies access to restarted native runtime even with persisted IDs')
        cli(OWNER,'--session',SESSION,'session','share','disable')
        check(not os.path.exists(SHARED),'owner can disable broker bound to stale native runtime')
        cli(OWNER,'--session',SESSION,'session','share','enable','--group','herdr-test')
        check(result(1001,'spaces')['workspaces']==[],'new native runtime starts without imported host runtime grants')
        cli(OWNER,'--session',SESSION,'session','share','disable')
        qualify_old_native()
        print(json.dumps(dict(passed=len(RESULTS),checks=RESULTS,skipped=SKIPPED),indent=2))
    finally:
        try:cli(OWNER,'--session',SESSION,'server','stop')
        except Exception:server.terminate()
        try:server.wait(timeout=10)
        except subprocess.TimeoutExpired:server.kill();server.wait()


if __name__=='__main__':
    main()
