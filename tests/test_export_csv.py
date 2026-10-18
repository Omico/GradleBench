#!/usr/bin/env python3
"""Boundary tests for faithful CSV extraction, independent of a Gradle install."""
import csv,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import export_csv as exporter
class Export(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.source=self.root/'results/test';self.output=self.root/'data';self.scope=patch.object(exporter,'ROOT',self.root);self.scope.start();self.addCleanup(self.scope.stop)
    def read(self,name):
        with (self.output/(name+'.csv')).open(newline='') as stream:return list(csv.DictReader(stream))
    def stage(self,name='formal/01-7.5.1/full/full',status='success'):
        stage=self.source/name;stage.mkdir(parents=True)
        launcher=dict(pid=1,ppid=0,start='same',rss_kib=10240,command='/jdk/bin/java org.gradle.wrapper.GradleWrapperMain');daemon=dict(pid=2,ppid=1,start='same',rss_kib=102400,command='/jdk/bin/java org.gradle.launcher.daemon.bootstrap.GradleDaemon 7.5.1')
        snapshots=[dict(seconds=0,phase='build',processes=[launcher,daemon]),dict(seconds=.15,phase='build',processes=[dict(launcher,rss_kib=102400),dict(daemon,rss_kib=10240,command='(java)')]),dict(seconds=.3,phase='resident',processes=[dict(daemon,rss_kib=81920)])]
        metadata=dict(command=[str(self.root/'gradlew'),'assembleDebug','-Ddescription=a,b\nquoted "value"'],cwd=str(self.root),gradle_user_home=str(self.root/'.state/homes/7.5.1'),java_home='/jdk')
        (stage/'command.json').write_text(json.dumps(metadata));(stage/'processes.jsonl').write_text(''.join(json.dumps(s)+'\n' for s in snapshots))
        result=dict(version='7.5.1',scenario='full',status=status,exit_code=0 if status=='success' else 1,seconds=12 if status=='success' else 999,peak_jvm_sum_mib=110,peak_daemon_mib=100,resident_jvm_median_mib=80,resident_daemon_median_mib=80,samples=3,max_sample_gap_seconds=.15)
        (stage/'result.json').write_text(json.dumps(result));return stage
    def export(self):return exporter.extract(self.source,self.output)
    def test_abbreviated_identity_and_synchronous_peak_are_preserved(self):
        # Independent process peaks are 100+100; the actual synchronous total is 110.
        self.stage();self.export();row=self.read('measurements')[0]
        self.assertEqual(float(row['peak_jvm_sum_mib']),110)
        samples=self.read('samples');self.assertEqual([int(x['jvm_sum_kib']) for x in samples],[112640,112640,81920])
        daemon=next(r for r in self.read('processes') if r['pid']=='2');self.assertEqual(daemon['role'],'daemon')
        self.assertEqual(self.read('rss')[3]['command_abbreviated'],'true')
    def test_failed_round_retained_but_excluded_from_performance_statistics(self):
        self.stage();self.stage('formal/02-7.5.1/full/full','java_heap_oom');self.export()
        self.assertEqual(len(self.read('measurements')),2)
        stat=next(r for r in self.read('summary') if r['version']=='7.5.1' and r['metric']=='seconds')
        self.assertEqual((stat['attempts'],stat['successes'],float(stat['mean'])),('2','1',12))
    def test_incomplete_measurement_blocks_export(self):
        stage=self.stage();(stage/'result.json').unlink()
        with self.assertRaisesRegex(ValueError,'missing completed measurement'):self.export()
    def test_csv_quotes_newlines_and_machine_path_normalization(self):
        self.stage();self.export();commands=self.read('commands')
        self.assertEqual(commands[0]['argument'],'${PROJECT}/gradlew');self.assertEqual(commands[2]['argument'],'-Ddescription=a,b\nquoted "value"')
    def test_inconsistent_raw_rss_blocks_publication(self):
        stage=self.stage();path=stage/'result.json';r=json.loads(path.read_text());r['peak_jvm_sum_mib']=200;path.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'raw data disagrees'):self.export()

    def test_only_completed_current_protocol_is_selected(self):
        # A later incomplete run and a different plan cannot replace completed data.
        for name,count,date,scenes in [('complete',16,'2026-10-18T10:00:00+08:00',['full','hot']),('partial',15,'2026-10-18T11:00:00+08:00',['full','hot']),('different-plan',16,'2026-10-18T12:00:00+08:00',['configuration','full','hot'])]:
            base=self.root/'results'/name;base.mkdir(parents=True)
            (base/'plan.json').write_text(json.dumps(dict(protocol=exporter.PROTOCOL,scenarios=scenes,formal_measurements=16)))
            (base/'environment.json').write_text(json.dumps(dict(time=date)))
            for i in range(count):
                p=base/'formal'/str(i)/'result.json';p.parent.mkdir(parents=True);p.write_text('{}')
        self.assertEqual(exporter.latest_source(),self.root/'results/complete')
if __name__=='__main__':unittest.main(verbosity=2)
