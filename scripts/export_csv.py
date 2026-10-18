#!/usr/bin/env python3
"""Export immutable local benchmark evidence as portable, lossless CSV tables."""
import argparse,csv,datetime,hashlib,json,re,statistics,tempfile
from pathlib import Path
from locking import benchmark_lock,project_path
ROOT=Path(__file__).resolve().parents[1]
PROTOCOL='deferred-full-finalization-v2'
METRICS=['seconds','peak_daemon_mib','peak_jvm_sum_mib','resident_daemon_median_mib','resident_jvm_median_mib']
SCHEMAS={
 'measurements':['measurement_id','phase','warmup_mode','round','version','scenario','status','exit_code','seconds','peak_daemon_mib','peak_jvm_sum_mib','resident_daemon_median_mib','resident_jvm_median_mib','samples','max_sample_gap_seconds','source_hash','started_at','daemon_pid','daemon_start','same_daemon','launch_delay_after_full_seconds','bookkeeping_after_resident_seconds','compiled_java_tasks','executed_tasks','aars','from_cache','error'],
 'samples':['measurement_id','sample_id','seconds','phase','jvm_count','jvm_sum_kib','daemon_max_kib'],
 'rss':['measurement_id','sample_id','pid','start','ppid','rss_kib','command_abbreviated'],
 'processes':['measurement_id','pid','start','role','command'],
 'gc':['unit_id','source_file','line_number','timestamp','uptime_seconds','level','tags','gc_id','heap_before_mib','heap_after_mib','heap_capacity_mib','pause_ms','raw_line'],
 'heap':['measurement_id','pid','command','exit_code','error','heap_used_mib','heap_committed_mib','metaspace_used_mib','metaspace_committed_mib','output'],
 'pressure':['measurement_id','boundary','line_number','raw_line'],
 'commands':['measurement_id','argument_index','argument'],
 'context':['measurement_id','property','value'],
 'cleanup':['unit_id','marker','confirmed','remaining_count','started_at','completed_at'],
 'signals':['unit_id','pid','start','signal'],
 'fixture':['path','sha256'],
 'environment':['property','value'],
 'dependencies':['version','path','sha256'],
 'summary':['scenario','version','metric','attempts','successes','n','median','minimum','maximum','mean'],
 'comparison':['scenario','metric','a_median','b_median','change_percent'],
 'sources':['path','sha256','bytes'],
}

def require(condition,message):
    if not condition:raise ValueError(message)

def read(path):return json.loads(path.read_text())

def portable(value):
    text=str(value)
    # Preserve recorded paths while normalizing machine-specific prefixes.
    text=text.replace(str(ROOT),'${PROJECT}')
    text=text.replace('/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home','${JDK17}')
    return text.replace('/opt/homebrew/share/android-commandlinetools','${ANDROID_SDK}')

def write_csv(path,fields,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='raise',lineterminator='\n');writer.writeheader()
        for row in rows:
            writer.writerow({k:('true' if v else 'false') if isinstance(v,bool) else v for k,v in row.items()})

def role(command):
    if 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in command:return 'daemon'
    if 'org.gradle.wrapper.GradleWrapperMain' in command:return 'launcher'
    return 'jvm' if Path(command.split()[0]).name in ['java','java.exe'] else 'other'

def stats(values):
    return dict(n=len(values),median=statistics.median(values),minimum=min(values),maximum=max(values),mean=statistics.mean(values)) if values else dict(n=0,median=None,minimum=None,maximum=None,mean=None)

def extract(source,destination):
    tables={key:[] for key in SCHEMAS};consumed=set();units={};gcfiles={}
    def load(path):consumed.add(path);return read(path)
    def lines(path):consumed.add(path);return path.read_text().splitlines()
    fixture_path=source/'fixture.json';fixture=load(fixture_path) if fixture_path.exists() else {}
    tables['fixture']=[dict(path=p,sha256=h) for p,h in sorted(fixture.get('files',{}).items())]
    env_path=source/'environment.json'
    if env_path.exists():
        env=load(env_path)
        for key,value in env.items():
            if key=='commands':continue
            tables['environment'].append(dict(property=key,value=portable(value)))
        for record in env['commands']:
            command=record['command']
            # uname contains the private host name; platform/machine above retain OS details.
            if command[0]=='uname':continue
            tables['environment'].append(dict(property='probe:'+portable(' '.join(command)),value=portable(record['output'])))
    dep=source/'dependency-cache-hashes.json'
    if dep.exists():
        for version,files in load(dep).items():
            tables['dependencies'] += [dict(version=version,path=p,sha256=h) for p,h in sorted(files.items())]
    toolchain=source/'toolchain-hashes.json'
    if toolchain.exists():
        tables['environment'] += [dict(property='sha256:'+portable(p),value=h) for p,h in load(toolchain).items()]
    for command_path in sorted((source/'formal').rglob('command.json')):
        stage=command_path.parent;relative=stage.relative_to(source);mid=relative.as_posix();meta=load(command_path)
        require(len(relative.parts)==4 and relative.parts[2]=='full' and stage.name in ['full','hot'],f'{stage}: unsupported formal scenario')
        result_path=stage/'result.json'
        require(result_path.is_file(),f'{stage}: missing completed measurement')
        result=load(result_path)
        round_number=relative.parts[1].split('-',1)[0]
        evidence=result.get('evidence',{});daemons=result.get('daemons',[])
        row={key:result.get(key) for key in SCHEMAS['measurements'] if key in result}
        row.update(measurement_id=mid,phase='formal',warmup_mode='',round=round_number,version=result.get('version',Path(meta['gradle_user_home']).name),scenario=result.get('scenario',stage.name),status=result['status'],source_hash=result.get('source_hash',meta.get('source_hash',fixture.get('sha256'))))
        if daemons:require(len(daemons)==1,f'{stage}: multiple daemon identities');row.update(daemon_pid=daemons[0]['pid'],daemon_start=daemons[0]['start'])
        for key in ['same_daemon','launch_delay_after_full_seconds','bookkeeping_after_resident_seconds','compiled_java_tasks','executed_tasks','aars','from_cache']:
            if key in evidence:row[key]=evidence[key]
        tables['measurements'].append(row)
        tables['commands'] += [dict(measurement_id=mid,argument_index=i,argument=portable(arg)) for i,arg in enumerate(meta['command'])]
        tables['context'] += [dict(measurement_id=mid,property=k,value=portable(v)) for k,v in sorted(meta.items()) if k!='command']
        ancestor=stage
        while ancestor!=source and not (ancestor/'unit.json').is_file():ancestor=ancestor.parent
        if (ancestor/'unit.json').exists():units[ancestor.relative_to(source).as_posix()]=ancestor
        for log in stage.glob('gc-*.log'):gcfiles[log]=ancestor.relative_to(source).as_posix()
        raw=stage/'processes.jsonl'
        if raw.exists():
            snapshots=[json.loads(line) for line in lines(raw)];identities={}
            for snap in snapshots:
                for proc in snap['processes']:
                    key=(proc['pid'],proc['start'])
                    if len(proc['command'])>len(identities.get(key,{}).get('command','')):identities[key]=proc
            roles={key:role(p['command']) for key,p in identities.items()}
            tables['processes'] += [dict(measurement_id=mid,pid=key[0],start=key[1],role=roles[key],command=portable(p['command'])) for key,p in sorted(identities.items())]
            series=[]
            for index,snap in enumerate(snapshots):
                jvms=[p for p in snap['processes'] if roles[(p['pid'],p['start'])] in ['daemon','launcher','jvm']]
                ds=[p for p in snap['processes'] if roles[(p['pid'],p['start'])]=='daemon']
                point=dict(measurement_id=mid,sample_id=index,seconds=snap['seconds'],phase=snap['phase'],jvm_count=len(jvms),jvm_sum_kib=sum(p['rss_kib'] for p in jvms),daemon_max_kib=max([p['rss_kib'] for p in ds],default=0));series.append(point)
                tables['rss'] += [dict(measurement_id=mid,sample_id=index,pid=p['pid'],start=p['start'],ppid=p['ppid'],rss_kib=p['rss_kib'],command_abbreviated=p['command']=='(java)') for p in snap['processes']]
            tables['samples']+=series
            original_csv=stage/'samples.csv'
            if original_csv.exists():
                consumed.add(original_csv)
                with original_csv.open(newline='') as stream:original=list(csv.DictReader(stream))
                require(len(original)==len(series),f'{stage}: CSV sample count differs')
                for a,b in zip(original,series):
                    require(all(float(a[key])==b[key] for key in ['jvm_sum_kib','daemon_max_kib','jvm_count']),f'{stage}: RSS CSV disagrees with raw snapshots')
            if result:
                active=[p for p in series if p['phase']=='build'];resident=[p for p in series if p['phase']=='resident']
                derived=dict(peak_jvm_sum_mib=max(p['jvm_sum_kib'] for p in active)/1024,peak_daemon_mib=max(p['daemon_max_kib'] for p in active)/1024,resident_jvm_median_mib=statistics.median(p['jvm_sum_kib'] for p in resident)/1024,resident_daemon_median_mib=statistics.median(p['daemon_max_kib'] for p in resident)/1024)
                for key,value in derived.items():require(value==result[key],f'{stage}: raw data disagrees with {key}')
        heap=stage/'heap.json'
        if heap.exists():
            for record in load(heap):
                item=dict(measurement_id=mid,pid=record.get('pid'),command=record.get('command'),exit_code=record.get('exit'),error=record.get('error'),output=portable(record.get('output','')))
                match=re.search(r'garbage-first heap\s+total (\d+)K, used (\d+)K',item['output'])
                if match:item.update(heap_committed_mib=int(match[1])/1024,heap_used_mib=int(match[2])/1024)
                match=re.search(r'Metaspace\s+used (\d+)K, committed (\d+)K',item['output'])
                if match:item.update(metaspace_used_mib=int(match[1])/1024,metaspace_committed_mib=int(match[2])/1024)
                tables['heap'].append(item)
        pressure=stage/'pressure.json'
        if pressure.exists():
            data=load(pressure)
            for boundary in ['before','after']:
                for i,line in enumerate(data[boundary]['output'].splitlines(),1):tables['pressure'].append(dict(measurement_id=mid,boundary=boundary,line_number=i,raw_line=portable(line)))
    for log,unit in sorted(gcfiles.items()):
        for i,line in enumerate(lines(log),1):
            item=dict(unit_id=unit,source_file=log.relative_to(source).as_posix(),line_number=i,raw_line=portable(line))
            match=re.match(r'^\[([^]]+)\]\[([0-9.]+)s\]\[([^]]+)\]\[([^]]+)\]',line)
            if match:item.update(timestamp=match[1],uptime_seconds=match[2],level=match[3].strip(),tags=match[4].strip())
            match=re.search(r'GC\((\d+)\)',line)
            if match:item['gc_id']=int(match[1])
            match=re.search(r'(\d+)M->(\d+)M\((\d+)M\)',line)
            if match:item.update(heap_before_mib=int(match[1]),heap_after_mib=int(match[2]),heap_capacity_mib=int(match[3]))
            match=re.search(r'\bPause.* ([\d.]+)ms$',line)
            if match:item['pause_ms']=float(match[1])
            tables['gc'].append(item)
    for unit,base in sorted(units.items()):
        metadata=load(base/'unit.json');path=base/'cleanup.json'
        if not path.exists():continue
        cleanup=load(path);tables['cleanup'].append(dict(unit_id=unit,marker=metadata['marker'],confirmed=cleanup.get('confirmed'),remaining_count=len(cleanup.get('remaining',[])),started_at=cleanup.get('started_at'),completed_at=cleanup.get('completed_at')))
        for action in cleanup.get('actions',[]):tables['signals'].append(dict(unit_id=unit,pid=action['pid'],start=action['start'],signal=action['signal']))
    formal=[r for r in tables['measurements'] if r['phase']=='formal']
    expected=read(source/'summary.json')['groups'] if (source/'summary.json').exists() else None
    if expected is not None:consumed.add(source/'summary.json')
    for scene in sorted({r['scenario'] for r in formal}):
        for version in ['7.5.1','7.6.6']:
            attempts=[r for r in formal if r['scenario']==scene and r['version']==version];good=[r for r in attempts if r['status']=='success']
            for metric in METRICS:
                stat=stats([r[metric] for r in good if r.get(metric) is not None]);item=dict(scenario=scene,version=version,metric=metric,attempts=len(attempts),successes=len(good),**stat);tables['summary'].append(item)
                if expected:require(stat==expected[scene][version]['metrics'][metric],f'{source}: summary differs from recorded statistics')
        for metric in METRICS:
            a,b=[next(r['median'] for r in tables['summary'] if r['scenario']==scene and r['metric']==metric and r['version']==v) for v in ['7.5.1','7.6.6']]
            tables['comparison'].append(dict(scenario=scene,metric=metric,a_median=a,b_median=b,change_percent=(b-a)/a*100 if a not in (None,0) and b is not None else None))
    tables['sources']=[dict(path=p.relative_to(source).as_posix(),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),bytes=p.stat().st_size) for p in sorted(consumed)]
    for table,fields in SCHEMAS.items():
        if tables[table]:write_csv(destination/(table+'.csv'),fields,tables[table])
    return dict(dataset='corrected',protocol=PROTOCOL,source_directory=source.relative_to(ROOT).as_posix(),measurements=len(tables['measurements']),formal=len(formal),warmup=0,validation=0,calibration=0,samples=len(tables['samples']),process_samples=len(tables['rss']),gc_lines=len(tables['gc']),source_hash=fixture.get('sha256',''))

def latest_source():
    candidates=[]
    for path in (ROOT/'results').glob('*/plan.json'):
        try:plan=read(path)
        except (OSError,json.JSONDecodeError):continue
        if plan.get('protocol')==PROTOCOL and plan.get('scenarios')==['full','hot'] and plan.get('formal_measurements')==16 and len(list((path.parent/'formal').rglob('result.json')))==16:
            created=datetime.datetime.fromisoformat(read(path.parent/'environment.json')['time'])
            candidates.append((created,path.parent))
    require(bool(candidates),'No completed sixteen-measurement run found; pass --source or run ./run.sh first')
    return max(candidates)[1]

def export(destination,source=None):
    destination=project_path(ROOT,destination);staging_parent=project_path(ROOT,ROOT/'.state/csv-export');staging_parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=staging_parent) as tmp:
        staging=Path(tmp)
        source=project_path(ROOT,source or latest_source())
        plan=read(source/'plan.json')
        require(plan['protocol']==PROTOCOL and plan['scenarios']==['full','hot'] and plan['formal_measurements']==16,'Unsupported benchmark plan')
        require(source.is_dir(),f'Missing local raw data: {source}. Existing CSV remains usable without results/.')
        info=extract(source,staging)
        require(info['formal']==info['measurements']==16,'Expected exactly 16 formal measurements')
        print('corrected:',info['measurements'],'formal measurements,',info['samples'],'samples',flush=True)
        write_csv(staging/'dataset.csv',list(info),[info])
        manifest=[]
        for file in sorted(staging.rglob('*.csv')):
            with file.open(newline='') as stream:count=sum(1 for _ in csv.reader(stream))-1
            manifest.append(dict(path=file.relative_to(staging).as_posix(),rows=count,bytes=file.stat().st_size,sha256=hashlib.sha256(file.read_bytes()).hexdigest()))
        write_csv(staging/'manifest.csv',['path','rows','bytes','sha256'],manifest)
        from verify_csv import verify
        verify(staging)
        for file in sorted(staging.rglob('*.csv')):
            target=project_path(ROOT,destination/file.relative_to(staging));target.parent.mkdir(parents=True,exist_ok=True);file.replace(target)
    return info

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,help='Completed current-protocol raw run; defaults to the newest completed run');parser.add_argument('--output',type=Path,default=ROOT/'data');args=parser.parse_args()
    with benchmark_lock(ROOT):export(args.output,source=args.source)
