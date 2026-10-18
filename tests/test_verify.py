#!/usr/bin/env python3
import datetime,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import bench,verify

class Audit(unittest.TestCase):
    def setUp(self):
        import csv
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'configuration';self.path.mkdir()
        self.unit=dict(schema_version=2,marker='testmarker');self.home=Path('/test/jdk17')
        owner=bench.Owner(self.unit['marker'])
        self.prepared=bench.prepare_measure('7.5.1','configuration',self.path/'unused',owner,source_hash='fixture')
        # Build a synthetic, internally consistent capture without starting processes.
        self.prepared['command']=[a.replace(str(self.path/'unused'),str(self.path)) for a in self.prepared['command']]
        bench.dump(self.path/'command.json',dict(command=self.prepared['command'],marker='testmarker',cwd=str(bench.ROOT),gradle_user_home=str(bench.ROOT/'.state/homes/7.5.1'),java_home=str(self.home),offline=True,source_hash='fixture'))
        proc=dict(pid=2,ppid=1,start='same start',rss_kib=2048,command=str(self.home/'bin/java')+' -Dgradlescope.owner=testmarker org.gradle.launcher.daemon.bootstrap.GradleDaemon 7.5.1')
        self.snaps=[dict(seconds=t,phase=phase,processes=[dict(proc)]) for t,phase in [(0,'build'),(.15,'build'),(.3,'build'),*[(.31+i*.15,'resident') for i in range(20)]]]
        self.save_snapshots()
        rows=[dict(seconds=snap['seconds'],phase=snap['phase'],jvm_sum_kib=2048,daemon_max_kib=2048,jvm_count=1) for snap in self.snaps]
        with (self.path/'samples.csv').open('w') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        self.result=dict(version='7.5.1',scenario='configuration',status='success',exit_code=0,seconds=.305,source_hash='fixture',monotonic_start=0,monotonic_end=.305,resident_window_end=3.31,daemons=[dict(pid=2,start='same start')],evidence=dict(configured=True),**bench.summarize_samples(rows))
        bench.dump(self.path/'result.json',self.result)
        bench.dump(self.path/'capture.json',dict(self.result,status='command_exited'))
        (self.path/'build.log').write_text('GRADLESCOPE_CONFIGURED modules=1000 directEdges=900\nBUILD SUCCESSFUL in 0s\n')
    def save_snapshots(self):
        (self.path/'processes.jsonl').write_text(''.join(json.dumps(s)+'\n' for s in self.snaps))
    def audit(self):
        from verify import audit_stage
        return audit_stage(self.path,self.unit,'7.5.1','configuration',True)
    def test_consistent_capture_and_untrusted_evidence(self):
        self.result['evidence']['configured']=False;bench.dump(self.path/'result.json',self.result)
        self.assertEqual(self.audit()['derived']['peak_jvm_sum_mib'],2)
    def test_wrong_actual_flag_rejected_despite_claimed_success(self):
        p=self.path/'command.json';data=json.loads(p.read_text());data['command']=[a.replace('--no-build-cache','--build-cache') for a in data['command']];bench.dump(p,data)
        with self.assertRaisesRegex(ValueError,'fixed option'):self.audit()
    def test_missing_log_proof_rejected_despite_evidence_flag(self):
        (self.path/'build.log').write_text('BUILD SUCCESSFUL\n')
        with self.assertRaisesRegex(ValueError,'configuration assertion'):self.audit()
    def test_incorrect_independent_peak_sum_rejected(self):
        self.result['peak_jvm_sum_mib']=4;bench.dump(self.path/'result.json',self.result)
        with self.assertRaisesRegex(ValueError,'statistic mismatch'):self.audit()
    def test_unrelated_process_cannot_enter_rss_total(self):
        fake=dict(pid=77,ppid=1,start='same start',rss_kib=1024,command='/usr/bin/python3 read.py testmarker')
        self.snaps[0]['processes'].append(fake);self.save_snapshots()
        with self.assertRaisesRegex(ValueError,'ownership'):self.audit()

class RunAudit(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.out=self.root/'run'
        input_file=self.root/'input.txt';input_file.write_text('fixture')
        files={'input.txt':hashlib.sha256(input_file.read_bytes()).hexdigest()}
        self.digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        fixture=dict(files=files,sha256=self.digest)
        order=['7.5.1','7.6.6','7.6.6','7.5.1']*2
        for i,v in enumerate(order,1):
            for scene in ['full','hot']:
                p=self.out/'formal'/f'{i:02d}-{v}'/'full'/scene/'result.json';p.parent.mkdir(parents=True);p.write_text('{}')
        dependencies={}
        for version in verify.VERSIONS:
            p=self.root/'.state/homes'/version/'caches/modules-2/files-2.1/artifact';p.parent.mkdir(parents=True);p.write_text('same')
            dependencies[version]={'artifact':hashlib.sha256(p.read_bytes()).hexdigest()}
        self.records={self.root/'fixture.json':fixture,self.out/'fixture.json':fixture,
            self.out/'plan.json':dict(protocol='deferred-full-finalization-v2',scenarios=['full','hot'],formal_measurements=16,order=order),
            self.out/'environment.json':dict(commands=[dict(command=['java','-version'],output='openjdk version "17.0.20.1"')]),
            self.out/'dependency-cache-hashes.json':dependencies,self.out/'toolchain-hashes.json':{}}
    def unit(self,base,version,scenes,offline,gc_version):
        # Unique mock identities/exit times isolate aggregate coverage from per-stage tests.
        index=self.calls;self.calls+=1
        start=datetime.datetime(2026,10,18,tzinfo=datetime.timezone.utc)+datetime.timedelta(seconds=index*2)
        stages=[dict(result=dict(status='success',source_hash=self.digest),metadata=dict(source_hash=self.digest)) for scene in scenes]
        return dict(stages=stages,identities={(index,'unique start')},jdks={'jdk17'},limits=[],chronology=dict(path=str(base),start=start.isoformat(),daemon_exit=(start+datetime.timedelta(seconds=1)).isoformat()))
    def test_aggregate_audits_all_twenty_units_and_sixteen_formal_measurements(self):
        self.calls=0
        with patch.object(verify,'ROOT',self.root),patch.object(verify,'read',side_effect=lambda p:self.records[p]),patch.object(verify,'audit_unit',side_effect=self.unit):
            report=verify.audit(self.out)
        self.assertEqual(self.calls,20);self.assertEqual(report['formal_measurements'],16)
        self.assertEqual(report['successful'],16);self.assertEqual(report['status'],'pass')
    def test_input_mismatch_stops_before_process_evidence_is_admitted(self):
        self.records[self.out/'fixture.json']=dict(self.records[self.root/'fixture.json'],sha256='different')
        with patch.object(verify,'ROOT',self.root),patch.object(verify,'read',side_effect=lambda p:self.records[p]),patch.object(verify,'audit_unit') as unit:
            with self.assertRaisesRegex(ValueError,'Run fixture differs'):verify.audit(self.out)
            unit.assert_not_called()

if __name__=='__main__':unittest.main(verbosity=2)
