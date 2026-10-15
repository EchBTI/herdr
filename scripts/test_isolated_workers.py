#!/usr/bin/env python3
"""Opt-in actual Herdr isolated-worker qualification in a disposable Linux container.

Requires rootless Bubblewrap namespaces. Never mount host homes or account files.
The test creates only disposable fixture accounts and project data in its image.
"""
import json
import os
import pathlib
import shlex
import socket
import subprocess
import sys
import time

import test_shared_access as fixture

CHECKS = []

def check(condition, label):
    assert condition, label
    CHECKS.append(label)
    print('PASS', label, flush=True)

def wait_for(path):
    for _ in range(250):
        if path.exists():
            return json.loads(path.read_text())
        time.sleep(.05)
    raise AssertionError('worker result missing: ' + str(path))

def fail_cli(*args):
    result = subprocess.run([fixture.BIN, '--session', fixture.SESSION, *args],
        preexec_fn=fixture.identity(fixture.OWNER), env=fixture.env(fixture.OWNER),
        capture_output=True, text=True, timeout=20)
    assert result.returncode != 0, (args, result.stdout, result.stderr)
    return result

def rpc(method, params=None):
    return fixture.result(fixture.OWNER, method, params, private=True)

PROBE = r'''
import ctypes,errno,json,os,pathlib,socket,subprocess
project=pathlib.Path.cwd(); checks={}
checks['project_write'] = project.joinpath('worker-owned').write_text('allowed') == 7
checks['unprivileged_uid'] = os.geteuid() != 0
checks['owner_files_absent'] = not pathlib.Path('/home/owner/OWNER_PRIVATE_WORKER_TEST').exists()
checks['sibling_project_absent'] = not pathlib.Path(SIBLING).exists()
checks['project_symlink_cannot_reach_owner'] = not project.joinpath('outside').exists()
checks['owner_api_absent'] = not pathlib.Path(OWNER_API).exists()
checks['private_home'] = os.environ['HOME'] == '/home/herdr-worker'
checks['owner_environment_absent'] = 'OWNER_ONLY_CREDENTIAL' not in os.environ and 'SSH_AUTH_SOCK' not in os.environ
status=pathlib.Path('/proc/self/status').read_text()
checks['no_new_privileges'] = 'NoNewPrivs:\t1' in status
checks['capabilities_dropped'] = 'CapEff:\t0000000000000000' in status
try:
 os.kill(OWNER_PID,0);checks['owner_process_unreachable']=False
except ProcessLookupError:checks['owner_process_unreachable']=True
except PermissionError:checks['owner_process_unreachable']=True
libc=ctypes.CDLL(None,use_errno=True)
checks['owner_ptrace_denied'] = libc.ptrace(16,OWNER_PID,None,None)==-1 and ctypes.get_errno() in (errno.ESRCH,errno.EPERM)
checks['private_process_tree'] = len([p for p in pathlib.Path('/proc').iterdir() if p.name.isdigit()]) < 10
fd_targets=[]
for descriptor in pathlib.Path('/proc/self/fd').iterdir():
 try:fd_targets.append(os.readlink(descriptor))
 except OSError:pass
checks['owner_descriptors_absent'] = not any(target.startswith('/home/owner/') or target.startswith(SIBLING) for target in fd_targets)
for label,family,address in [('host_loopback_unavailable',socket.AF_INET,('127.0.0.1',PORT)),('host_abstract_socket_unavailable',socket.AF_UNIX,'\0herdr-worker-qualification')]:
 s=socket.socket(family);s.settimeout(.2)
 try:s.connect(address);checks[label]=False
 except OSError:checks[label]=True
 finally:s.close()
def request(method,params,token=None):
 s=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect(os.environ['HERDR_SOCKET_PATH'])
 value={'id':'worker-probe','method':'worker.execute.v1','params':{'token':os.environ['HERDR_WORKER_TOKEN'] if token is None else token,'request':{'id':'worker-probe','method':method,'params':params}}}
 s.sendall(json.dumps(value).encode()+b'\n');result=json.loads(s.makefile('rb').readline(131072));s.close();return result
pane=os.environ['HERDR_PANE_ID']
checks['scoped_reporting'] = 'result' in request('pane.report_metadata',{'pane_id':pane,'source':'worker-test','title':'ISOLATED_REPORT'})
checks['scoped_passive_read'] = 'result' in request('pane.read',{'pane_id':pane,'source':'visible','format':'text','strip_ansi':True})
checks['global_operation_denied'] = 'error' in request('server.stop',{})
checks['other_project_denied'] = 'error' in request('pane.get',{'pane_id':OTHER_PANE})
checks['forged_capability_denied'] = 'error' in request('pane.get',{'pane_id':pane},'0'*64)
if project.joinpath('retired-token').exists():
 checks['retired_capability_denied'] = 'error' in request('pane.get',{'pane_id':pane},project.joinpath('retired-token').read_text())
checks['cli_scoped_integration'] = subprocess.run(['/run/herdr/herdr','pane','get',pane],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=8).returncode==0
project.joinpath('generation-token').write_text(os.environ['HERDR_WORKER_TOKEN'])
project.joinpath('checks.json').write_text(json.dumps(checks))
'''

def main():
    if (os.environ.get('HERDR_SHARED_TEST_DISPOSABLE') != '1' or not pathlib.Path('/.dockerenv').exists()
            or sys.platform != 'linux' or os.geteuid() != 0 or sys.flags.optimize):
        raise SystemExit('Refusing: explicitly opted-in disposable Linux root Docker image required; no host homes or account configuration mounts.')
    fixture.setup()
    base = pathlib.Path('/srv') / fixture.SESSION
    base.mkdir(mode=0o755)
    projects = [base/'one', base/'two']
    for project in projects:
        project.mkdir(mode=0o700);os.chown(project,fixture.OWNER,fixture.OWNER)
    (projects[1]/'credential').write_text('OTHER_PROJECT_VALUE')
    pathlib.Path('/home/owner/OWNER_PRIVATE_WORKER_TEST').write_text('OWNER_PRIVATE_VALUE')
    (projects[0]/'outside').symlink_to('/home/owner/OWNER_PRIVATE_WORKER_TEST')
    tcp=socket.socket();tcp.bind(('127.0.0.1',0));tcp.listen()
    abstract=socket.socket(socket.AF_UNIX);abstract.bind('\0herdr-worker-qualification');abstract.listen()
    log=open('/tmp/'+fixture.SESSION+'-workers.log','w')
    daemon_env=dict(fixture.env(fixture.OWNER),OWNER_ONLY_CREDENTIAL='OWNER_PRIVATE_ENV',SSH_AUTH_SOCK='/tmp/owner-agent-unavailable')
    def start():
        process=subprocess.Popen([fixture.BIN,'--session',fixture.SESSION,'server'],preexec_fn=fixture.identity(fixture.OWNER),env=daemon_env,stdout=log,stderr=log)
        fixture.wait(fixture.PRIVATE)
        for _ in range(100):
            if 'result' in fixture.request(fixture.OWNER,'ping',{},private=True):break
            time.sleep(.05)
        assert process.poll() is None
        assert 'result' in fixture.request(fixture.OWNER,'ping',{},private=True)
        return process
    def stop(process):
        fixture.cli(fixture.OWNER,'--session',fixture.SESSION,'server','stop');process.wait(timeout=15)
    def processes_with(marker):
        matches=[]
        for entry in pathlib.Path('/proc').iterdir():
            if entry.name.isdigit():
                try:
                    if marker in (entry/'cmdline').read_bytes().split(b'\0'):matches.append(int(entry.name))
                except (FileNotFoundError,ProcessLookupError,PermissionError):pass
        return matches
    def lifecycle_process(pane,label):
        marker='herdr-lifecycle-'+fixture.SESSION+'-'+label
        code="import subprocess,time;subprocess.Popen(['sleep','300']);time.sleep(300)"
        rpc('pane.send_text',{'pane_id':pane,'text':'python3 -c '+shlex.quote(code)+' '+shlex.quote(marker)+'\n'})
        for _ in range(100):
            parents=processes_with(marker.encode())
            if parents:break
            time.sleep(.05)
        check(bool(parents),'actual worker lifecycle process started: '+label)
        descendants=set(parents)
        time.sleep(.1)
        for entry in pathlib.Path('/proc').iterdir():
            if entry.name.isdigit():
                try:
                    fields=(entry/'status').read_text().splitlines()
                    parent=int(next(line for line in fields if line.startswith('PPid:')).split()[1])
                    if parent in descendants:descendants.add(int(entry.name))
                except (FileNotFoundError,ProcessLookupError,StopIteration):pass
        check(len(descendants)>len(parents),'worker spawned a child for lifecycle qualification: '+label)
        return descendants
    def wait_processes_gone(pids,label):
        def active(pid):
            try:return not any(line.startswith('State:') and 'Z' in line for line in pathlib.Path('/proc',str(pid),'status').read_text().splitlines())
            except FileNotFoundError:return False
        for _ in range(100):
            if not any(active(pid) for pid in pids):break
            time.sleep(.05)
        check(not any(active(pid) for pid in pids),label)
    server=start()
    try:
        for index,project in enumerate(projects):
            rpc('workspace.create',{'label':'worker-'+str(index),'cwd':str(project)})
        snapshot=rpc('session.snapshot')['snapshot']
        spaces=[w['workspace_id'] for w in snapshot['workspaces']]
        panes=[next(p['pane_id'] for p in snapshot['panes'] if p['workspace_id']==w) for w in spaces]
        fail_cli('session','worker','enable','--space',spaces[0],'--project',str(projects[0]),'--ack-restart')
        check(True,'live trusted PTYs cannot be silently relabelled isolated')
        stop(server)
        snapshot_path=pathlib.Path(fixture.PRIVATE).parent/'session.json'
        check(json.loads(snapshot_path.read_text())['version']==3,'ordinary sessions retain snapshot version 3 compatibility')
        for space,project in zip(spaces,projects):
            result=json.loads(fixture.cli(fixture.OWNER,'--session',fixture.SESSION,'session','worker','enable','--space',space,'--project',str(project),'--ack-restart'))
            check(result['execution']=='isolated worker' and result['network']=='none','offline worker opt-in records explicit execution and network policy')
        check(json.loads(snapshot_path.read_text())['version']==4,'offline isolation migration raises snapshot version before worker restoration')
        # A repository configuration must not start an owner-side helper after isolation.
        subprocess.run(['git','init',str(projects[0])],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        config=projects[0]/'.git/config'
        config.write_text(config.read_text()+'\n[core]\n\tfsmonitor = touch /home/owner/FS_MONITOR_MUST_STAY_ABSENT\n')
        for file in (projects[0]/'.git').rglob('*'):
            os.chown(file,fixture.OWNER,fixture.OWNER)
        os.chown(projects[0]/'.git',fixture.OWNER,fixture.OWNER)
        server=start()
        status=json.loads(fixture.cli(fixture.OWNER,'--session',fixture.SESSION,'session','worker','status'))
        check(all(status['workspaces'][space]['mode']=='isolated' for space in spaces),'actual restarted panes report isolated execution identity')
        script=PROBE.replace('SIBLING',repr(str(projects[1]/'credential'))).replace('OWNER_API',repr(fixture.PRIVATE)).replace('OTHER_PANE',repr(panes[1])).replace('PORT',str(tcp.getsockname()[1])).replace('OWNER_PID',str(server.pid))
        (projects[0]/'probe.py').write_text(script)
        rpc('pane.send_text',{'pane_id':panes[0],'text':'python3 '+shlex.quote(str(projects[0]/'probe.py'))+'\n'})
        for label,passed in wait_for(projects[0]/'checks.json').items():check(passed,label)
        before={pane['pane_id'] for pane in rpc('session.snapshot')['snapshot']['panes']}
        rpc('pane.split',{'target_pane_id':panes[0],'direction':'right'})
        after=rpc('session.snapshot')['snapshot']['panes']
        added=[pane['pane_id'] for pane in after if pane['pane_id'] not in before]
        check(len(added)==1,'isolated panes retain native split support with scoped cwd and launch identity')
        rpc('pane.send_text',{'pane_id':added[0],'text':'printf worker-split > split-result\n'})
        for _ in range(100):
            if (projects[0]/'split-result').exists():break
            time.sleep(.05)
        check((projects[0]/'split-result').read_text()=='worker-split','new isolated pane executes only within its project')
        split_processes=lifecycle_process(added[0],'pane-close')
        rpc('pane.close',{'pane_id':added[0]})
        wait_processes_gone(split_processes,'closing a worker pane terminates its process namespace')
        check(not pathlib.Path('/home/owner/FS_MONITOR_MUST_STAY_ABSENT').exists(),'host Git helpers never execute isolated repository configuration')
        token=(projects[0]/'generation-token').read_text()
        (projects[0]/'retired-token').write_text(token)
        generation_processes=lifecycle_process(panes[0],'server-crash')
        server.kill();server.wait(timeout=15)
        wait_processes_gone(generation_processes,'server crash terminates the previous worker generation')
        server=start()
        (projects[0]/'checks.json').unlink()
        rpc('pane.send_text',{'pane_id':panes[0],'text':'python3 '+shlex.quote(str(projects[0]/'probe.py'))+'\n'})
        check(all(wait_for(projects[0]/'checks.json').values()),'isolated worker recovery retains the execution boundary')
        check((projects[0]/'generation-token').read_text()!=token,'full runtime restart retires the previous broker capability generation')
        stop(server)
        state=pathlib.Path(fixture.PRIVATE).parent
        registry=state/'isolated-workers/access-policy.json'
        registry.rename(registry.with_suffix('.saved'))
        server=start()
        check('error' in fixture.request(fixture.OWNER,'server.live_handoff',{},private=True),'missing worker registry still forbids unsafe live handoff')
        recovered=rpc('session.snapshot')['snapshot']
        check(all('error' in fixture.request(fixture.OWNER,'pane.send_text',{'pane_id':pane,'text':'printf MUST_NOT_RUN\n'},private=True) for pane in panes), 'missing worker profile cannot fall back to owner execution')
        check(not json.loads(fixture.cli(fixture.OWNER,'--session',fixture.SESSION,'session','worker','status'))['workspaces'], 'unavailable worker profiles are not reported as active isolation')
        stop(server)
        registry.with_suffix('.saved').rename(registry)
        for space in spaces:
            fixture.cli(fixture.OWNER,'--session',fixture.SESSION,'session','worker','disable','--space',space,'--ack-restart')
        check(json.loads(snapshot_path.read_text())['version']==3,'disabling the last isolated space restores ordinary snapshot compatibility')
        print(json.dumps({'passed':len(CHECKS),'checks':CHECKS},indent=2))
    finally:
        if server.poll() is None:
            try:stop(server)
            except Exception:server.kill();server.wait()
        tcp.close();abstract.close();log.close()

if __name__=='__main__':main()
