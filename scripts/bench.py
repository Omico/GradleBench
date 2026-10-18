#!/usr/bin/env python3
"""macOS/Linux serial benchmark; all process ownership is scoped to this run."""
import argparse, csv, datetime, hashlib, json, os, platform, re, shutil, signal, statistics, subprocess, sys, time, uuid
from pathlib import Path
from generate import ROOT, fingerprint, module_path
from prepare import select
from locking import benchmark_lock,project_path
VERSIONS=['7.5.1','7.6.6']
INTERVAL=.15
RESIDENT=3.0
JDK=Path(os.environ.get('GRADLESCOPE_JAVA_HOME','/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home'))
SDK=Path(os.environ.get('ANDROID_SDK_ROOT',os.environ.get('ANDROID_HOME','/opt/homebrew/share/android-commandlinetools')))

def dump(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n')

def capture(cmd):
    p=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    return dict(command=cmd,status=p.returncode,output=p.stdout)

def table():
    p=subprocess.run(['ps','-ww','-axo','pid=,ppid=,lstart=,rss=,stat=,command='],capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'},check=True)
    return parse_ps(p.stdout)

def parse_ps(text):
    result={}
    for line in text.splitlines():
        parts=line.split(None,9)
        if len(parts)!=10 or parts[8].startswith('Z'): continue
        pid,ppid,*_=parts
        result[int(pid)]=dict(pid=int(pid),ppid=int(ppid),start=' '.join(parts[2:7]),rss_kib=int(parts[7]),command=parts[9])
    return result

def identity(p): return (p['pid'],p['start'])

def owned(snapshot, marker, known):
    # A marker mentioned by an unrelated reader is not proof of ownership.
    prop=re.compile(r'(?:^|\s)-Dgradlescope\.owner='+re.escape(marker)+r'(?=\s|$)')
    gc=re.compile(r'-Xlog:[^\n]*?file=[^\n]*?/gc-'+re.escape(marker)+r'-(?:%p|\d+)\.log(?=[:\s]|$)')
    def marked_java(p):
        tokens=p['command'].split();exe=Path(tokens[0]).name
        if exe not in ('java','java.exe'):return False
        # Do not authorize application arguments that merely quote a JVM option.
        i=1
        paired={'-cp','-classpath','--class-path','-p','--module-path','--add-opens','--add-exports','--add-reads','--add-modules','--limit-modules','--patch-module'}
        while i<len(tokens) and tokens[i].startswith('-'):
            if tokens[i] in ('-jar','-m','--module'):break
            i+=2 if tokens[i] in paired else 1
        options=' '.join(tokens[:i])
        return bool(prop.search(options) or gc.search(options))
    found={pid:p for pid,p in snapshot.items() if identity(p) in known or marked_java(p)}
    changed=True
    while changed:
        changed=False
        for pid,p in snapshot.items():
            if pid not in found and p['ppid'] in found:
                found[pid]=p; changed=True
    return found

def is_jvm(p):
    executable=p['command'].split()[0]
    return p.get('kind') in ('jvm','daemon') or Path(executable).name in ('java','java.exe','(java)')

def signal_identity(p, sig, snapshot=None):
    current=(snapshot if snapshot is not None else table()).get(p['pid'])
    if current and identity(current)==identity(p):
        try: os.kill(p['pid'],sig)
        except ProcessLookupError: pass
        return True
    return False

class Owner:
    def __init__(self,marker,journal=None):
        self.marker=marker; self.known=set(); self.inventory={}; self.journal=journal
        self.last_cleanup=dict(confirmed=False,actions=[])
        self.admissions={}
        if journal:dump(journal,dict(marker=marker,identities=[]))
    def scan(self):
        found=owned(table(), self.marker,self.known)
        changed=False
        for p in found.values():
            key=identity(p)
            previous=self.inventory.get(key,{})
            p['kind']='daemon' if 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in p['command'] else previous.get('kind','jvm' if is_jvm(p) else 'other')
            self.known.add(key); self.inventory[key]=p
            if key not in self.admissions:
                self.admissions[key]=dict(p);changed=True
        if changed and self.journal:
            dump(self.journal,dict(marker=self.marker,identities=list(self.admissions.values())))
        return found
    def cleanup(self):
        # Never uses global gradle --stop, pkill, or an unverified PID.
        actions=[]
        self.last_cleanup=dict(confirmed=False,actions=actions,started_at=datetime.datetime.now().astimezone().isoformat())
        for sig,window in [(signal.SIGTERM,8),(signal.SIGKILL,4)]:
            found=self.scan()
            for p in found.values():
                if signal_identity(p,sig): actions.append(dict(pid=p['pid'],start=p['start'],signal=int(sig)))
            deadline=time.monotonic()+window
            while time.monotonic()<deadline:
                found=self.scan()
                if not found:
                    self.last_cleanup.update(confirmed=True,remaining=[],completed_at=datetime.datetime.now().astimezone().isoformat())
                    return self.last_cleanup
                time.sleep(.15)
        found=self.scan()
        if found:
            self.last_cleanup['remaining']=list(found.values())
            raise RuntimeError(f'Cleanup not confirmed; STOP: {found}')
        self.last_cleanup.update(confirmed=True,remaining=[],completed_at=datetime.datetime.now().astimezone().isoformat())
        return self.last_cleanup

def point(found,elapsed,phase):
    java=[p for p in found.values() if is_jvm(p)]
    daemon=[p for p in java if p.get('kind')=='daemon' or 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in p['command']]
    return dict(seconds=elapsed,phase=phase,jvm_sum_kib=sum(p['rss_kib'] for p in java),daemon_max_kib=max([p['rss_kib'] for p in daemon],default=0),jvm_count=len(java))

def summarize_samples(rows):
    active=[x for x in rows if x['phase']=='build']
    resident=[x for x in rows if x['phase']=='resident']
    return dict(peak_jvm_sum_mib=max(x['jvm_sum_kib'] for x in active)/1024 if active else None,
                peak_daemon_mib=max(x['daemon_max_kib'] for x in active)/1024 if active else None,
                resident_jvm_median_mib=statistics.median([x['jvm_sum_kib'] for x in resident])/1024 if resident else None,
                resident_daemon_median_mib=statistics.median([x['daemon_max_kib'] for x in resident])/1024 if resident else None,
                samples=len(rows), max_sample_gap_seconds=max([b['seconds']-a['seconds'] for a,b in zip(rows,rows[1:])],default=0))

def classify(code,log,timed_out=False):
    if timed_out:return 'timeout'
    if code==0:return 'success'
    if 'java.lang.OutOfMemoryError: Java heap space' in log or 'java.lang.OutOfMemoryError: GC overhead limit exceeded' in log:return 'java_heap_oom'
    if 'java.lang.OutOfMemoryError' in log:return 'jvm_oom_other'
    if code<0 or 'daemon disappeared' in log.lower():return 'unknown_termination'
    return 'build_error'

def environment(out):
    commands=[['uname','-a'],[str(JDK/'bin/java'),'-version'],['df','-h',str(ROOT)]]
    if platform.system()=='Darwin':commands += [['sysctl','-n','hw.ncpu'],['sysctl','-n','hw.memsize'],['vm_stat'],['memory_pressure'],['sysctl','vm.swapusage']]
    else:commands += [['cat','/proc/meminfo'],['cat','/sys/fs/cgroup/memory.max'],['cat','/sys/fs/cgroup/memory/memory.limit_in_bytes']]
    data=[capture(c) for c in commands]
    info=dict(time=datetime.datetime.now().astimezone().isoformat(),platform=platform.platform(),machine=platform.machine(),jdk=str(JDK),sdk=str(SDK),heap='6g',workers=4,interval=INTERVAL,resident_seconds=RESIDENT,timeout_seconds=1800,commands=data,container_limit='macOS native host; Linux cgroup not applicable' if platform.system()=='Darwin' else 'see cgroup probes',selection_reason='64 GiB host, existing pressure/compression: fixed 6 GiB heap, 4 workers to leave headroom; no tuning by version')
    dump(out,info)
    return info

def preflight():
    for path in [ROOT/'.state',ROOT/'.gradle',ROOT/'gradle/wrapper',*[module_path(ROOT,i) for i in range(1000)]]:project_path(ROOT,path)
    if not (JDK/'bin/java').exists():raise RuntimeError('JDK missing; set GRADLESCOPE_JAVA_HOME to JDK 17')
    j=capture([str(JDK/'bin/java'),'-version'])['output']
    if not re.search(r'version "17[.]',j):raise RuntimeError('JDK must be 17')
    for p in ['platforms/android-33/android.jar','build-tools/30.0.3/aapt2','licenses/android-sdk-license']:
        if not (SDK/p).is_file():raise RuntimeError(f'SDK prerequisite missing: {p}; do not auto-accept licenses')
    snapshot=table() # Abort if process inventory inaccessible.
    for journal in (ROOT/'.state/owners').glob('*.json'):
        data=json.loads(journal.read_text())
        remaining=owned(snapshot,data['marker'],{identity(p) for p in data['identities']})
        if remaining:raise RuntimeError(f'Previous experiment processes still alive: {remaining}')
    leftovers=[p for p in snapshot.values() if str(ROOT/'results') in p['command'] and 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in p['command']]
    if leftovers:raise RuntimeError(f'Previous experiment daemon still alive; stop before measuring: {leftovers}')
    actual=fingerprint()
    if actual!=json.loads((ROOT/'fixture.json').read_text()):raise RuntimeError('Source/topology hash drift')

def clean_outputs():
    # Strictly bounded project outputs; dependency caches remain intact.
    paths=[project_path(ROOT,p) for p in [ROOT/'build',*[module_path(ROOT,i)/'build' for i in range(1000)]]]
    for p in paths:
        if p.exists():shutil.rmtree(p)

def gradle_env(home,marker):
    env={k:v for k,v in os.environ.items() if k not in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','GRADLE_OPTS','JAVA_OPTS','_JAVA_OPTIONS']}
    env.update(JAVA_HOME=str(JDK),GRADLE_USER_HOME=str(home),ANDROID_HOME=str(SDK),ANDROID_SDK_ROOT=str(SDK),JAVA_OPTS=f'-Dgradlescope.owner={marker}',LC_ALL='en_US.UTF-8')
    return env

def prepare_measure(v,scenario,out,owner,offline=True,jvmargs=None,source_hash=None):
    out.mkdir(parents=True,exist_ok=False)
    home=ROOT/'.state/homes'/v
    args=jvmargs or f'-Xms512m -Xmx6g -XX:+UseG1GC -Dfile.encoding=UTF-8 -Dgradlescope.owner={owner.marker} -Xlog:gc*:file={out}/gc-{owner.marker}-%p.log:time,uptime,level,tags'
    task={'configuration':'help','resolution':'resolveAllDebug','full':'assembleDebug','hot':'assembleDebug'}[scenario]
    cmd=[str(ROOT/'gradlew'),task,'--daemon','--no-configuration-cache','--no-configure-on-demand','--no-build-cache','--no-parallel','--no-watch-fs','--max-workers=4','--console=plain','--warning-mode=all','--stacktrace','--no-scan',f'-Dorg.gradle.jvmargs={args}',f'-Dgradlescope.resolution={out}/resolution.json']
    if offline:cmd.append('--offline')
    source_hash=source_hash or fingerprint()['sha256']
    dump(out/'command.json',dict(command=cmd,cwd=str(ROOT),gradle_user_home=str(home),java_home=str(JDK),offline=offline,marker=owner.marker,source_hash=source_hash))
    return dict(command=cmd,home=home,jvmargs=args,source_hash=source_hash)


def validate_pair(full,hot):
    same=bool(full['daemons']) and full['daemons']==hot['daemons']
    hot['evidence']['same_daemon']=same
    errors=[]
    if not same:errors.append('daemon identity changed')
    if full['status']!='success':errors.append('full build prerequisite failed')
    if errors:
        hot.setdefault('validation_errors',[]).extend(errors)
        # Keep OOM, timeout and ordinary failure categories intact.
        if hot['status']=='success':hot['status']='validation_error'


def measure(v,scenario,out,owner,offline=True,prepared=None,deferred=None):
    prepared=prepared or prepare_measure(v,scenario,out,owner,offline)
    cmd=prepared['command'];home=prepared['home']
    log=(out/'build.log').open('w');processes=(out/'processes.jsonl').open('w')
    rows=[];seen={};timed_out=False;completed=False;proc=None
    before=capture(['vm_stat']) if platform.system()=='Darwin' else capture(['cat','/proc/meminfo'])
    prepared['pressure_before']=before
    start=time.monotonic();wall_start=datetime.datetime.now().astimezone().isoformat()
    def take_sample(phase):
        tick=time.monotonic();found=owner.scan();elapsed=tick-start
        rows.append(point(found,elapsed,phase))
        for p in found.values():seen[identity(p)]=dict(p)
        processes.write(json.dumps(dict(seconds=elapsed,phase=phase,processes=list(found.values())))+'\n')
        return tick,elapsed
    def save_samples():
        if rows:
            with (out/'samples.csv').open('w') as f:
                writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    try:
        proc=subprocess.Popen(cmd,cwd=ROOT,env=gradle_env(home,owner.marker),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        snap=table()
        if proc.pid in snap:owner.known.add(identity(snap[proc.pid]))
        while True:
            tick,elapsed=take_sample('build')
            if proc.poll() is not None:break
            if elapsed>1800:
                timed_out=True
                try:owner.cleanup()
                finally:dump(out/'timeout-cleanup.json',owner.last_cleanup)
                proc.wait(timeout=10);break
            time.sleep(max(0,INTERVAL-(time.monotonic()-tick)))
        end=time.monotonic();duration=end-start
        resident_start=time.monotonic()
        while time.monotonic()-resident_start<RESIDENT:
            tick,_=take_sample('resident')
            time.sleep(max(0,INTERVAL-(time.monotonic()-tick)))
        resident_end=time.monotonic()
        log.close();processes.close()
        daemons=[p for p in seen.values() if p.get('kind')=='daemon' or 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in p['command']]
        result=dict(version=v,scenario=scenario,status='pending_validation',exit_code=proc.returncode,seconds=duration,
                    started_at=wall_start,monotonic_start=start,monotonic_end=end,resident_window_end=resident_end,
                    source_hash=prepared['source_hash'],daemons=[dict(pid=p['pid'],start=p['start']) for p in daemons])
        # Keep exit evidence durable even if interrupted before deferred finalization.
        dump(out/'capture.json',dict(result,status='command_exited'))
        def finish():
            text=(out/'build.log').read_text(errors='replace')
            status=classify(proc.returncode,text,timed_out)
            evidence=dict(configured='GRADLESCOPE_CONFIGURED modules=1000 directEdges=900' in text,
                          resolved='GRADLESCOPE_RESOLVED modules=1000 configurations=2000 components=3800 edges=1800' in text)
            if status=='success':
                if not evidence['configured']:status='validation_error'
                elif scenario=='resolution' and not evidence['resolved']:status='validation_error'
                elif scenario in ['full','hot']:
                    evidence.update(aars=len(list(ROOT.glob('modules/lib*/build/outputs/aar/*-debug.aar'))),
                        compiled_java_tasks=len(re.findall(r'> Task :lib\d+:compileDebugJavaWithJavac(?:\n|\r)',text)),
                        from_cache=len(re.findall(r'> Task .* FROM-CACHE',text)),
                        executed_tasks=len([line for line in text.splitlines() if line.startswith('> Task ') and not any(x in line for x in [' UP-TO-DATE',' NO-SOURCE',' SKIPPED'])]))
                    if evidence['aars']!=1000 or evidence['from_cache'] or (scenario=='full' and evidence['compiled_java_tasks']!=1000) or (scenario=='hot' and evidence['executed_tasks']!=0):status='validation_error'
            result.update(status=status,evidence=evidence,**summarize_samples(rows))
            for p in daemons:
                src=home/'daemon'/v/f"daemon-{p['pid']}.out.log"
                if src.exists():shutil.copy2(src,out/src.name)
            diagnostics=[]
            for p in ([] if scenario=='full' else daemons):
                now=table().get(p['pid'])
                if now and identity(now)==identity(p):
                    for command in ['GC.heap_info','VM.flags']:
                        try:
                            q=subprocess.run([str(JDK/'bin/jcmd'),str(p['pid']),command],capture_output=True,text=True,timeout=10)
                            diagnostics.append(dict(pid=p['pid'],command=command,exit=q.returncode,output=q.stdout+q.stderr))
                        except subprocess.TimeoutExpired:diagnostics.append(dict(pid=p['pid'],command=command,error='timeout'))
            dump(out/'heap.json',diagnostics)
            dump(out/'pressure.json',dict(before=before,after=prepared.get('pressure_after') or (capture(['vm_stat']) if platform.system()=='Darwin' else capture(['cat','/proc/meminfo'])),after_phase='before hot launch' if prepared.get('pressure_after') else 'after postprocessing'))
            save_samples();dump(out/'result.json',result)
            print(f"{v} {scenario}: {status} {duration:.2f}s RSS={result['peak_jvm_sum_mib']:.1f}MiB",flush=True)
        if deferred is not None:deferred.append(finish)
        else:finish()
        completed=True
        return result
    finally:
        log.close();processes.close()
        # Persist failure evidence before cleanup, which can itself fail.
        if not completed:
            save_samples()
            if not (out/'result.json').exists():
                error=sys.exc_info()[1]
                dump(out/'result.json',dict(version=v,scenario=scenario,status='interrupted' if isinstance(error,KeyboardInterrupt) else 'measurement_error',
                    exit_code=proc.poll() if proc else None,seconds=time.monotonic()-start,source_hash=prepared['source_hash'],
                    error=repr(error),evidence={},daemons=[],**summarize_samples(rows)))
        if proc is not None and proc.poll() is None:
            try:owner.cleanup()
            finally:dump(out/'emergency-cleanup.json',owner.last_cleanup)
            proc.wait(timeout=10)


def run_unit(v,base,scenarios,offline):
    select(v);marker='gs'+uuid.uuid4().hex
    owner=Owner(marker,project_path(ROOT,ROOT/'.state/owners'/f'{marker}.json'))
    dump(base/'unit.json',dict(schema_version=2,marker=marker,version=v,scenarios=scenarios,start=datetime.datetime.now().astimezone().isoformat()))
    results=[];pending=[]
    source=fingerprint()
    try:
        if owner.scan():raise RuntimeError('Fresh unit has unexpected processes')
        if source!=json.loads((ROOT/'fixture.json').read_text()):raise RuntimeError('Fixture drift')
        if 'full' in scenarios:clean_outputs()
        prepared={}
        for scene in scenarios:
            prepared[scene]=prepare_measure(v,scene,base/scene,owner,offline,
                jvmargs=prepared['full']['jvmargs'] if scene=='hot' else None,source_hash=source['sha256'])
        for scene in scenarios:
            results.append(measure(v,scene,base/scene,owner,offline,prepared[scene],pending if scene=='full' else None))
    finally:
        try:
            if 'hot' in locals().get('prepared',{}) and 'pressure_before' in prepared['hot']:
                prepared['full']['pressure_after']=prepared['hot']['pressure_before']
            for finish in pending:finish()
            if len(results)==2 and scenarios==['full','hot']:
                full,hot=results;validate_pair(full,hot)
                hot['evidence']['launch_delay_after_full_seconds']=hot['monotonic_start']-full['monotonic_end']
                hot['evidence']['bookkeeping_after_resident_seconds']=hot['monotonic_start']-full['resident_window_end']
                dump(base/'hot/result.json',hot)
            if fingerprint()!=source:
                for result in results:
                    result.setdefault('validation_errors',[]).append('fixture changed during unit')
                    if result['status']=='success':result['status']='validation_error'
                    dump(base/result['scenario']/'result.json',result)
                raise RuntimeError('Fixture drift during measurement')
        finally:
            try:owner.cleanup()
            finally:
                dump(base/'cleanup.json',owner.last_cleanup)
                dump(base/'inventory.json',list(owner.inventory.values()))
    return results

def toolchain_hashes():
    paths=[JDK/'release',JDK/'bin/java',JDK/'bin/javac',JDK/'lib/modules',
           SDK/'platforms/android-33/android.jar',SDK/'platforms/android-33/source.properties',
           SDK/'build-tools/30.0.3/aapt2',SDK/'build-tools/30.0.3/source.properties']
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}

def run(out):
    preflight()
    project_path(ROOT,ROOT/'local.properties').write_text(f'sdk.dir={SDK}\n')
    environment(out/'environment.json')
    dump(out/'fixture.json',fingerprint())
    tools=toolchain_hashes();dump(out/'toolchain-hashes.json',tools)
    dump(out/'plan.json',dict(protocol='deferred-full-finalization-v2',scenarios=['full','hot'],
        order=['7.5.1','7.6.6','7.6.6','7.5.1']*2,formal_measurements=16,
        warmup_scenarios=['configuration','resolution','full','hot'],warmup_modes=['online','offline']))
    for path in [*sorted((ROOT/'scripts').glob('*.py')),*sorted((ROOT/'tests').glob('*.py')),
                 ROOT/'run.sh',ROOT/'gradlew',ROOT/'gradle/wrapper/gradle-wrapper.jar']:
        target=out/'runner'/path.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
    dump(out/'runner-hashes.json',{str(p.relative_to(out/'runner')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (out/'runner').rglob('*') if p.is_file()})
    for v in VERSIONS:
        for offline in [False,True]:
            base=out/'warmup'/v/('offline' if offline else 'online')
            results=[]
            for scenarios in [['configuration'],['resolution'],['full','hot']]:
                results+=run_unit(v,base/scenarios[0],scenarios,offline)
            if any(r['status']!='success' for r in results):
                dump(out/'blocked.json',dict(reason='Warm-up failed; formal cache equivalence not established',version=v,offline=offline))
                raise RuntimeError('Warm-up failed; see raw logs. No formal scores claimed.')
    dependencies={}
    for v in VERSIONS:
        cache=ROOT/'.state/homes'/v/'caches/modules-2/files-2.1'
        dependencies[v]={str(p.relative_to(cache)):hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.rglob('*') if p.is_file()}
    dump(out/'dependency-cache-hashes.json',dependencies)
    if not dependencies[VERSIONS[0]] or dependencies[VERSIONS[0]]!=dependencies[VERSIONS[1]]:
        raise RuntimeError('Dependency caches differ before formal measurements')
    for index,v in enumerate(['7.5.1','7.6.6','7.6.6','7.5.1']*2,1):
        run_unit(v,out/'formal'/f'{index:02d}-{v}'/'full',['full','hot'],True)
    if toolchain_hashes()!=tools:raise RuntimeError('JDK/SDK changed during measurement')
    from verify import verify
    verify(out)
    from export_csv import export
    export(out/'csv',source=out)

def main(argv=None):
    parser=argparse.ArgumentParser(description='Run the fixed eight-pair ABBAABBA benchmark or check prerequisites')
    parser.add_argument('action',choices=['run','check'])
    parser.add_argument('--output',type=Path,help='New raw-results directory; existing directories are never overwritten')
    args=parser.parse_args(argv)
    out=args.output or ROOT/'results'/datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
    with benchmark_lock(ROOT):
        if args.action=='check':preflight();print('Preflight OK');return
        out=project_path(ROOT,out)
        out.mkdir(parents=True,exist_ok=False)
        def interrupted(sig,frame):raise KeyboardInterrupt(f'Signal {sig}')
        signal.signal(signal.SIGTERM,interrupted)
        try:
            from generate import generate
            generate(ROOT)
            preflight()
            from prepare import ensure
            ensure()
            subprocess.run([sys.executable,'-m','unittest','discover','-s',str(ROOT/'tests')],
                env={**os.environ,'PYTHONPATH':str(ROOT/'scripts')},check=True)
            run(out)
        except BaseException as error:
            dump(out/'interruption.json',dict(type=type(error).__name__,message=str(error)))
            raise

if __name__=='__main__':main()
