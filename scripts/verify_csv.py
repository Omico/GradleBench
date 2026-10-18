#!/usr/bin/env python3
"""Independently verify committed CSV data without results/, JDK or Android SDK."""
import argparse,collections,csv,hashlib,math,statistics
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
METRICS=['seconds','peak_daemon_mib','peak_jvm_sum_mib','resident_daemon_median_mib','resident_jvm_median_mib']
def require(condition,message):
    if not condition:raise ValueError(message)
def rows(path):
    if not path.exists():return []
    with path.open(encoding='utf-8',newline='') as stream:return list(csv.DictReader(stream))
def close(a,b):return math.isclose(float(a),float(b),rel_tol=1e-12,abs_tol=1e-9)
def verify(directory):
    require((directory/'manifest.csv').is_file(),'Missing CSV manifest')
    manifest=rows(directory/'manifest.csv')
    require({p.relative_to(directory).as_posix() for p in directory.rglob('*.csv')}=={r['path'] for r in manifest}|{'manifest.csv'},'Unexpected or missing CSV files')
    for item in manifest:
        path=directory/item['path']
        require(path.resolve().is_relative_to(directory.resolve()),'Manifest path escapes dataset')
        require(hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256'],'Checksum mismatch: '+item['path'])
        require(len(rows(path))==int(item['rows']),'Row count mismatch: '+item['path'])
    total=0
    datasets=rows(directory/'dataset.csv')
    require(len(datasets)==1 and datasets[0]['dataset']=='corrected','Expected one corrected-protocol dataset')
    for dataset in datasets:
        base=directory;measurements=rows(base/'measurements.csv');measure={r['measurement_id']:r for r in measurements}
        require(len(measurements)==16 and all(m['phase']=='formal' for m in measurements),'Only the latest 16 formal measurements belong here')
        require(len(measure)==len(measurements)==int(dataset['measurements']),'Missing/duplicate measurement')
        total+=len(measure)
        require(int(dataset['formal'])==16 and all(int(dataset[k])==0 for k in ['warmup','validation','calibration']),'Only formal measurements may be exported')
        processes={(p['measurement_id'],p['pid'],p['start']):p for p in rows(base/'processes.csv')}
        sums=collections.defaultdict(int);maxima=collections.defaultdict(int);jvmcounts=collections.Counter();seen=set()
        rss=rows(base/'rss.csv');require(len(rss)==int(dataset['process_samples']),'Process sample count mismatch')
        for p in rss:
            key=(p['measurement_id'],p['sample_id']);identity=(*key,p['pid'],p['start']);require(identity not in seen,'Duplicate process sample');seen.add(identity)
            identity=(p['measurement_id'],p['pid'],p['start']);require(identity in processes,'Unknown process identity');proc=processes[identity]
            require(int(p['rss_kib'])>=0,'Negative RSS')
            command=proc['command'];exe=Path(command.split()[0]).name
            java=exe in ['java','java.exe'];daemon=java and 'org.gradle.launcher.daemon.bootstrap.GradleDaemon' in command
            require((proc['role']=='daemon')==daemon,'Daemon role disagrees with command')
            require((proc['role'] in ['daemon','launcher','jvm'])==java,'JVM role disagrees with command')
            if java:sums[key]+=int(p['rss_kib']);jvmcounts[key]+=1
            if daemon:maxima[key]=max(maxima[key],int(p['rss_kib']))
        grouped=collections.defaultdict(list);samples=rows(base/'samples.csv');samplekeys=set()
        require(len(samples)==int(dataset['samples']),'RSS snapshot count mismatch')
        for sample in samples:
            key=(sample['measurement_id'],sample['sample_id']);require(key not in samplekeys,'Duplicate snapshot');samplekeys.add(key)
            require(sample['measurement_id'] in measure,'Snapshot has no measurement')
            require((int(sample['jvm_sum_kib']),int(sample['daemon_max_kib']),int(sample['jvm_count']))==(sums[key],maxima[key],jvmcounts[key]),'Synchronous RSS reconstruction mismatch')
            grouped[sample['measurement_id']].append(sample)
        require(all((p['measurement_id'],p['sample_id']) in samplekeys for p in rss),'Process row has no snapshot')
        for mid,m in measure.items():
            ss=grouped[mid];active=[p for p in ss if p['phase']=='build'];resident=[p for p in ss if p['phase']=='resident']
            require(active and resident,'Missing build/resident samples')
            derived={'peak_jvm_sum_mib':max(int(p['jvm_sum_kib']) for p in active)/1024,'peak_daemon_mib':max(int(p['daemon_max_kib']) for p in active)/1024,'resident_jvm_median_mib':statistics.median(int(p['jvm_sum_kib']) for p in resident)/1024,'resident_daemon_median_mib':statistics.median(int(p['daemon_max_kib']) for p in resident)/1024}
            require(int(m['samples'])==len(ss),'Measurement sample count mismatch')
            for metric,value in derived.items():require(close(value,m[metric]),'Measurement RSS mismatch: '+mid+'/'+metric)
            require(all(float(b['seconds'])>float(a['seconds']) for a,b in zip(ss,ss[1:])),'Non-monotonic samples')
        formal=[m for m in measurements if m['phase']=='formal']
        if formal:
            order={m['round']:m['version'] for m in formal}
            require([order[k] for k in sorted(order)]==['7.5.1','7.6.6','7.6.6','7.5.1']*2,'Formal order differs from ABBAABBA')
            require(len({(m['round'],m['scenario']) for m in formal})==len(formal),'Duplicate formal scenario')
            for round_number,version in order.items():
                pair={m['scenario']:m for m in formal if m['round']==round_number}
                require(set(pair)=={'full','hot'} and all(m['version']==version for m in pair.values()),'Round is not a full/hot pair of the same version')
                if all(m['status']=='success' for m in pair.values()):
                    require(bool(pair['full']['daemon_pid']) and all(pair['full'][k]==pair['hot'][k] for k in ['daemon_pid','daemon_start']) and pair['hot']['same_daemon']=='true','Successful hot build changed daemon')
        summaries=rows(base/'summary.csv');lookup={}
        for item in summaries:
            attempts=[m for m in formal if m['scenario']==item['scenario'] and m['version']==item['version']];good=[m for m in attempts if m['status']=='success'];values=[float(m[item['metric']]) for m in good if m[item['metric']]!='']
            require(len(attempts)==int(item['attempts']) and len(good)==int(item['successes']) and len(values)==int(item['n']),'Summary included excluded samples')
            if values:
                for key,value in dict(median=statistics.median(values),minimum=min(values),maximum=max(values),mean=statistics.mean(values)).items():require(close(value,item[key]),'Summary mismatch: '+key)
            else:require(all(item[k]=='' for k in ['median','minimum','maximum','mean']),'Unavailable statistics replaced with values')
            lookup[(item['scenario'],item['version'],item['metric'])]=item
        expected_keys={(m['scenario'],m['version'],metric) for m in formal for metric in METRICS}
        require(len(summaries)==len(lookup) and set(lookup)==expected_keys,'Summary coverage mismatch')
        comparisons=rows(base/'comparison.csv')
        expected_comparisons={(m['scenario'],metric) for m in formal for metric in METRICS}
        comparison_keys={(r['scenario'],r['metric']) for r in comparisons}
        require(len(comparisons)==len(comparison_keys) and comparison_keys==expected_comparisons,'Comparison coverage mismatch')
        for item in comparisons:
            a=lookup[(item['scenario'],'7.5.1',item['metric'])]['median'];b=lookup[(item['scenario'],'7.6.6',item['metric'])]['median']
            require(item['a_median']==a and item['b_median']==b,'Comparison references another group')
            if a and b and float(a)!=0:require(close((float(b)-float(a))/float(a)*100,item['change_percent']),'Change percentage mismatch')
            else:require(item['change_percent']=='','Unavailable change replaced with a value')
        require((base/'cleanup.csv').is_file(),'Missing cleanup records')
        cleanup=rows(base/'cleanup.csv')
        expected_units={f"formal/{m['round']}-{m['version']}/full" for m in formal}
        require(all(m['measurement_id']==f"formal/{m['round']}-{m['version']}/full/{m['scenario']}" for m in formal),'Measurement unit mismatch')
        cleanup_units={r['unit_id'] for r in cleanup}
        require(len(cleanup)==len(cleanup_units) and cleanup_units==expected_units,'Cleanup coverage mismatch')
        require(all(r['confirmed']=='true' and r['remaining_count']=='0' for r in cleanup),'Unconfirmed cleanup')
        print(dataset['dataset']+': PASS ('+str(len(measurements))+' measurements)',flush=True)
    print('CSV verification PASS:',total,'measurements; independent synchronous RSS/statistics reconstruction; no results/ required')
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path,nargs='?',default=ROOT/'data');args=parser.parse_args();verify(args.directory.resolve())
