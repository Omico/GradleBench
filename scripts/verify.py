#!/usr/bin/env python3
"""Independent checks of the current protocol's raw evidence and Android outputs."""
import argparse,csv,datetime,hashlib,io,json,math,re,statistics,struct,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
VERSIONS=['7.5.1','7.6.6']
def require(condition,detail):
    if not condition:raise ValueError(detail)
def read(path):return json.loads(path.read_text())

def audit_stage(path,unit,version,scene,offline):
    result=read(path/'result.json');metadata=read(path/'command.json');argv=metadata['command']
    label=str(path)
    require(unit.get('schema_version')==2,f'{label}: unsupported unit schema')
    captured=read(path/'capture.json')
    require(all(captured[k]==result[k] for k in ['exit_code','seconds','monotonic_start','monotonic_end','source_hash']),f'{label}: durable capture differs from final result')
    def check(condition,what):require(condition,f'{label}: {what}')
    check(result['version']==version and result['scenario']==scene,'result version/scenario mismatch')
    check(metadata['marker']==unit['marker'],'marker mismatch')
    check(argv[0]==str(ROOT/'gradlew'),'unexpected wrapper')
    check(argv[1]==dict(configuration='help',resolution='resolveAllDebug',full='assembleDebug',hot='assembleDebug')[scene],'wrong task')
    fixed=['--daemon','--no-configuration-cache','--no-configure-on-demand','--no-build-cache','--no-parallel','--no-watch-fs','--max-workers=4','--console=plain','--warning-mode=all','--stacktrace','--no-scan']
    check(all(argv.count(x)==1 for x in fixed),'missing or duplicate fixed option')
    check(metadata['offline']==offline and argv.count('--offline')==int(offline),'offline mismatch')
    check(metadata['cwd']==str(ROOT),'unexpected project root')
    check(metadata['gradle_user_home']==str(ROOT/'.state/homes'/version),'wrong Gradle user home')
    check(argv.count('-Dgradlescope.resolution='+str(path/'resolution.json'))==1,'resolution output mismatch')
    args=[x.removeprefix('-Dorg.gradle.jvmargs=') for x in argv if x.startswith('-Dorg.gradle.jvmargs=')]
    check(len(args)==1,'duplicate JVM options')
    options=args[0].split()
    fixedjvm=['-Xms512m','-Xmx6g','-XX:+UseG1GC','-Dfile.encoding=UTF-8','-Dgradlescope.owner='+unit['marker']]
    check(all(options.count(x)==1 for x in fixedjvm) and len(options)==6,'JVM settings differ')
    gc=[x for x in options if x.startswith('-Xlog:')]
    expectedgc=path.parent/'full' if scene=='hot' else path
    check(gc==[f'-Xlog:gc*:file={expectedgc}/gc-{unit["marker"]}-%p.log:time,uptime,level,tags'],'GC settings/path differ')
    check(set(argv)==set([str(ROOT/'gradlew'),argv[1],*fixed,*(['--offline'] if offline else []),'-Dorg.gradle.jvmargs='+args[0],'-Dgradlescope.resolution='+str(path/'resolution.json')]),'unexpected CLI option')
    snapshots=[json.loads(line) for line in (path/'processes.jsonl').read_text().splitlines()]
    check(bool(snapshots),'no snapshots')
    commands={}
    for snap in snapshots:
        for proc in snap['processes']:
            key=(proc['pid'],proc['start'])
            if len(proc['command'])>len(commands.get(key,{}).get('command','')):commands[key]=proc
    jvms={k for k,p in commands.items() if Path(p['command'].split()[0]).name in ['java','java.exe']}
    daemons={k for k in jvms if 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in commands[k]['command']}
    known=set();series=[];daemonseries=[];active=[];resident=[];resident_daemon=[]
    for n,snap in enumerate(snapshots):
        check(snap['phase'] in ['build','resident'],'unknown sample phase')
        check(math.isfinite(snap['seconds']) and snap['seconds']>=0,'invalid sample time')
        if n:check(snap['seconds']>snapshots[n-1]['seconds'],'sample times not increasing')
        current={p['pid']:p for p in snap['processes']}
        accepted=set()
        for pid,p in current.items():
            key=(pid,p['start']);tokens=p['command'].split()
            marked=(key in jvms and (('-Dgradlescope.owner='+unit['marker']) in tokens or any(t.startswith('-Xlog:') and '/gc-'+unit['marker']+'-%p.log:' in t for t in tokens)))
            if key in known or marked:accepted.add(pid)
        while True:
            more={pid for pid,p in current.items() if p['ppid'] in accepted}
            if more<=accepted:break
            accepted|=more
        check(accepted==set(current),'unproven process ownership in snapshot')
        known.update((p['pid'],p['start']) for p in current.values())
        total=sum(p['rss_kib'] for p in current.values() if (p['pid'],p['start']) in jvms)/1024
        d=max([p['rss_kib']/1024 for p in current.values() if (p['pid'],p['start']) in daemons],default=0)
        check(all(p['rss_kib']>=0 for p in current.values()),'negative RSS')
        series.append(total);daemonseries.append(d)
        if snap['phase']=='build':
            check(not resident,'build snapshot after resident window');active.append(total)
        else:resident.append(total);resident_daemon.append(d)
    check(bool(active) and bool(resident),'missing active or resident samples')
    active_count=len(active)
    derived=dict(peak_jvm_sum_mib=max(active),peak_daemon_mib=max(daemonseries[:active_count]),resident_jvm_median_mib=statistics.median(resident),resident_daemon_median_mib=statistics.median(resident_daemon),samples=len(snapshots),max_sample_gap_seconds=max(b['seconds']-a['seconds'] for a,b in zip(snapshots,snapshots[1:])))
    for key,value in derived.items():check(abs(value-result[key])<1e-8,'RSS/sample statistic mismatch: '+key)
    if result['status']=='success':check(0<=result['seconds']-snapshots[active_count-1]['seconds']<.3,'wall duration inconsistent with final active sample')
    check(snapshots[active_count]['seconds']>=result['seconds']-.01,'resident starts before command exit')
    check(2.7<=snapshots[-1]['seconds']-snapshots[active_count]['seconds']<=3.3,'resident window is not three seconds')
    with (path/'samples.csv').open(newline='') as stream:csvrows=list(csv.DictReader(stream))
    check(len(csvrows)==len(snapshots),'CSV length mismatch')
    for i,row in enumerate(csvrows):
        check(row['phase']==snapshots[i]['phase'] and float(row['seconds'])==snapshots[i]['seconds'],'CSV timing/phase mismatch')
        check(float(row['jvm_sum_kib'])==series[i]*1024 and float(row['daemon_max_kib'])==daemonseries[i]*1024,'CSV RSS mismatch')
    text=(path/'build.log').read_text()
    if result['status']=='success':
        check(result['exit_code']==0 and 'BUILD SUCCESSFUL' in text and 'BUILD FAILED' not in text,'claimed success disagrees with build log')
        check(text.count('GRADLESCOPE_CONFIGURED modules=1000 directEdges=900')==1,'configuration assertion missing or duplicated')
        check(len(daemons)==1,'not exactly one observed daemon')
        check(result['daemons']==[dict(pid=p[0],start=p[1]) for p in daemons],'recorded daemon identity incorrect')
        check(all(commands[k]['command'].split()[0]==str(Path(metadata['java_home'])/'bin/java') for k in jvms),'JVM uses another JDK')
        check(all(commands[k]['command'].endswith('GradleDaemon '+version) for k in daemons),'daemon runs different Gradle version')
        if offline:check('Downloading https://' not in text,'download occurred in offline formal run')
        if scene=='resolution':
            check(text.count('GRADLESCOPE_RESOLVED modules=1000 configurations=2000 components=3800 edges=1800')==1 and '> Task :resolveAllDebug' in text,'resolution task did not execute')
            graph=read(path/'resolution.json');rows=graph['rows']
            expected={(f':lib{i:04d}',c) for i in range(1000) for c in ['debugCompileClasspath','debugRuntimeClasspath']}
            check(len(rows)==2000 and {(r['module'],r['configuration']) for r in rows}==expected,'missing/duplicated graph configurations')
            check((graph['modules'],graph['configurations'],graph['components'],graph['edges'])==(1000,2000,3800,1800),'graph totals mismatch')
            check(all((r['components'],r['edges'])==((10,9) if int(r['module'][4:])%10==0 else (1,0)) for r in rows),'graph topology mismatch')
        if scene in ['full','hot']:
            check(' FROM-CACHE' not in text,'build cache hit')
            executed=[line for line in text.splitlines() if line.startswith('> Task ') and not any(x in line for x in [' UP-TO-DATE',' NO-SOURCE',' SKIPPED'])]
            if scene=='full':
                compiled=re.findall(r'^> Task :(lib\d{4}):compileDebugJavaWithJavac$',text,re.M)
                bundles=re.findall(r'^> Task :(lib\d{4}):bundleDebugAar$',text,re.M)
                expected={f'lib{i:04d}' for i in range(1000)}
                check(len(compiled)==1000 and set(compiled)==expected and len(bundles)==1000 and set(bundles)==expected,'not all modules compiled/packaged')
            else:check(not executed and '22900 actionable tasks: 22900 up-to-date' in text,'hot build is not no-op')
    return dict(result=result,metadata=metadata,derived=derived,identities=known,daemon_ids=daemons,jdk=metadata['java_home'])

def audit_unit(base,version,scenes,offline,gc_version):
    unit=read(base/'unit.json');cleanup=read(base/'cleanup.json')
    require(unit['version']==version and unit['scenarios']==scenes,f'{base}: unit metadata mismatch')
    require(cleanup['confirmed'] and not cleanup.get('remaining'),f'{base}: cleanup not confirmed')
    stages=[audit_stage(base/scene,unit,version,scene,offline) for scene in scenes]
    observed=set().union(*(d['identities'] for d in stages));daemons=set().union(*(d['daemon_ids'] for d in stages))
    inventory={(p['pid'],p['start']) for p in read(base/'inventory.json')}
    require(all((a['pid'],a['start']) in inventory&observed for a in cleanup['actions']),f'{base}: cleanup targeted unobserved process')
    exits=[];limits=[]
    for log in base.rglob('gc-*.log'):
        text=log.read_text()
        require(('Version: '+gc_version+'+') in text and 'Heap Max Capacity: 6G' in text and 'Using G1' in text,f'{log}: JVM configuration mismatch')
        endings=[line for line in text.splitlines() if '[gc,heap,exit]' in line]
        if endings:exits.append(datetime.datetime.fromisoformat(endings[-1].split(']')[0][1:]))
    successful=all(d['result']['status']=='success' for d in stages)
    if successful:require(len(exits)==len(daemons) and bool(exits),f'{base}: daemon GC exit evidence missing')
    elif len(exits)!=len(daemons) or not exits:limits.append('Failed unit lacks full GC exit evidence: '+str(base))
    if scenes==['full','hot']:
        full,hot=stages
        if successful:
            require(full['daemon_ids']==hot['daemon_ids'],f'{base}: hot daemon changed')
            require(next(x for x in full['metadata']['command'] if x.startswith('-Dorg.gradle.jvmargs='))==next(x for x in hot['metadata']['command'] if x.startswith('-Dorg.gradle.jvmargs=')),f'{base}: hot JVM args changed')
        for field,left in [('launch_delay_after_full_seconds','monotonic_end'),('bookkeeping_after_resident_seconds','resident_window_end')]:
            actual=hot['result']['monotonic_start']-full['result'][left]
            require(abs(hot['result']['evidence'][field]-actual)<1e-8,f'{base}: handoff timing mismatch')
        require(not read(base/'full/heap.json'),f'{base}: heap diagnostic between full and hot')
    return dict(stages=stages,identities=observed,jdks={d['jdk'] for d in stages},limits=limits,
        chronology=dict(path=str(base),start=unit['start'],daemon_exit=max(exits).isoformat() if exits else cleanup['completed_at']))

def audit(root):
    root=root.resolve();plan=read(root/'plan.json')
    require(plan['protocol']=='deferred-full-finalization-v2' and plan['scenarios']==['full','hot'] and plan['formal_measurements']==16,'Unsupported benchmark plan')
    order=['7.5.1','7.6.6','7.6.6','7.5.1']*2
    require(plan['order']==order,'Plan is not ABBAABBA')
    rounds=sorted((root/'formal').iterdir())
    require([p.name for p in rounds]==[f'{i:02d}-{v}' for i,v in enumerate(order,1)],'Formal rounds differ from ABBAABBA')
    require({p.relative_to(root/'formal').as_posix() for p in (root/'formal').rglob('result.json')}=={f'{rd.name}/full/{scene}/result.json' for rd in rounds for scene in ['full','hot']},'Unexpected/missing formal measurement')
    fixture=read(root/'fixture.json')
    require(fixture==read(ROOT/'fixture.json'),'Run fixture differs from current workspace; use verify_csv.py for a saved CSV snapshot')
    live={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in fixture['files']}
    digest=hashlib.sha256(json.dumps(live,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    require(live==fixture['files'] and digest==fixture['sha256'],'Fixture files drifted')
    env=read(root/'environment.json')
    gc_version=re.search(r'version "([^"]+)"',next(c['output'] for c in env['commands'] if c['command'][-1]=='-version')).group(1)
    expected=[]
    for version in VERSIONS:
        for mode in ['online','offline']:
            for scenes in [['configuration'],['resolution'],['full','hot']]:expected.append((root/'warmup'/version/mode/scenes[0],version,scenes,mode=='offline',False))
    expected.extend((rd/'full',version,['full','hot'],True,True) for rd,version in zip(rounds,order))
    seen=set();jdks=set();units=[];limits=[];formal=[]
    for base,version,scenes,offline,scored in expected:
        checked=audit_unit(base,version,scenes,offline,gc_version)
        require(not checked['identities']&seen,f'{base}: process identity reused across cold units')
        seen|=checked['identities'];jdks|=checked['jdks'];units.append(checked['chronology']);limits+=checked['limits']
        for stage in checked['stages']:
            require(stage['result']['source_hash']==stage['metadata']['source_hash']==digest,f'{base}: source hash differs')
            if scored:formal.append(stage['result'])
            else:require(stage['result']['status']=='success',f'{base}: warm-up failed')
    require(len(jdks)==1,'JDK differs across units')
    for previous,current in zip(units,units[1:]):
        require(datetime.datetime.fromisoformat(previous['daemon_exit'])<datetime.datetime.fromisoformat(current['start']),f'Overlapping cold units: {previous["path"]}, {current["path"]}')
    dependencies={}
    for version in VERSIONS:
        cache=ROOT/'.state/homes'/version/'caches/modules-2/files-2.1'
        dependencies[version]={p.relative_to(cache).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in cache.rglob('*') if p.is_file()}
    require(bool(dependencies[VERSIONS[0]]) and dependencies[VERSIONS[0]]==dependencies[VERSIONS[1]]==read(root/'dependency-cache-hashes.json')[VERSIONS[0]],'Dependency cache hashes differ')
    require(read(root/'dependency-cache-hashes.json')==dependencies,'Recorded dependency cache differs')
    for path,digest in read(root/'toolchain-hashes.json').items():require(hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest,'JDK/SDK file changed: '+path)
    return dict(status='pass_with_limits' if limits else 'pass',formal_measurements=16,successful=sum(r['status']=='success' for r in formal),source_hash=fixture['sha256'],cold_units=20,cleanup_chronology=units,raw_rss_and_csv='all agree',limits=limits)

def verify_outputs(required=True):
    aars=list(ROOT.glob('modules/lib*/build/outputs/aar/*-debug.aar'))
    if not required and len(aars)!=1000:return dict(retained_aars=len(aars),classfiles_target_java11=0,dependency_hubs_checked=0,output_validation='unavailable after failed final build')
    require(len(aars)==1000,'Expected 1000 current AARs')
    classes=0;hubs=0
    for aar in aars:
        with zipfile.ZipFile(aar) as archive:
            with zipfile.ZipFile(io.BytesIO(archive.read('classes.jar'))) as jar:
                name=aar.name.split('-')[0];data=jar.read(f'org/gradlescope/{name}/Value.class')
                require(data[:4]==bytes.fromhex('cafebabe') and struct.unpack('>H',data[6:8])[0]==55,f'{aar}: Java 11 target required');classes+=1
                index=int(name[3:])
                if index%10==0:
                    require(all(f'org/gradlescope/lib{i:04d}/Value'.encode() in data for i in range(index+1,index+10)),f'{aar}: missing dependency type');hubs+=1
    require(hubs==100,'Expected 100 dependency hubs')
    return dict(retained_aars=len(aars),classfiles_target_java11=classes,dependency_hubs_checked=hubs,output_validation='current workspace artifacts')

def verify(out):
    from locking import project_path
    out=project_path(ROOT,out)
    independent=audit(out)
    last=out/'formal/08-7.5.1/full'
    artifacts=verify_outputs(required=all(read(last/scene/'result.json')['status']=='success' for scene in ['full','hot']))
    report=dict(independent_audit=independent,**artifacts)
    (out/'verification.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    print('Raw benchmark verification:',independent['status'],flush=True)
    return report

if __name__=='__main__':
    from locking import benchmark_lock
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path);args=parser.parse_args()
    with benchmark_lock(ROOT):verify(args.output)
