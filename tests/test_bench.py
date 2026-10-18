#!/usr/bin/env python3
import json, os, signal, subprocess, tempfile, time, unittest, uuid
from pathlib import Path
from unittest.mock import patch
import bench

class Logic(unittest.TestCase):
    def test_generated_modules_live_under_modules_without_project_renaming(self):
        from generate import generate,fingerprint
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fixture=generate(root)
            self.assertEqual(len(list((root/'modules').glob('lib[0-9][0-9][0-9][0-9]'))),1000)
            self.assertFalse(list(root.glob('lib*')))
            self.assertEqual(len(fixture['files']),4003)
            self.assertEqual(fixture,fingerprint(root))
            self.assertIn('project(":${name}").projectDir = file("modules/${name}")',(root/'settings.gradle').read_text())
            self.assertIn("implementation project(':lib0001')",(root/'modules/lib0000/build.gradle').read_text())

    def test_run_preserves_warmup_and_exact_eight_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'new';out.mkdir();calls=[]
            for name in ['run.sh','gradlew','gradle/wrapper/gradle-wrapper.jar']:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture')
            for version in bench.VERSIONS:
                p=root/'.state/homes'/version/'caches/modules-2/files-2.1/artifact';p.parent.mkdir(parents=True,exist_ok=True);p.write_text('same')
            def unit(version,base,scenarios,offline):
                calls.append((version,str(base.relative_to(out)),scenarios,offline));return [dict(status='success') for _ in scenarios]
            with patch('bench.ROOT',root),patch('bench.preflight'),patch('bench.environment'),patch('bench.fingerprint',return_value=dict(sha256='fixture')),patch('bench.run_unit',side_effect=unit),patch('bench.toolchain_hashes',return_value={}),patch('verify.verify'),patch('export_csv.export') as export:
                bench.run(out)
                export.assert_called_once_with(out/'csv',source=out)
            warm=[x for x in calls if x[1].startswith('warmup/')];formal=[x for x in calls if x[1].startswith('formal/')]
            self.assertEqual(len(warm),12);self.assertEqual(sum(len(x[2]) for x in warm),16)
            self.assertEqual([x[0] for x in formal],['7.5.1','7.6.6','7.6.6','7.5.1']*2)
            self.assertTrue(all(x[2]==['full','hot'] and x[3] for x in formal))
            self.assertEqual(json.loads((out/'plan.json').read_text())['formal_measurements'],16)

    def test_simultaneous_peak_not_sum_of_peaks(self):
        # Distinct individual peaks at different timestamps: true total is 110, not 200.
        rows=[]
        for t,values in enumerate([(100,10),(10,100)]):
            found={i:dict(pid=i,command='/jdk/bin/java org.gradle.launcher.daemon.bootstrap.GradleDaemon' if i==1 else '/jdk/bin/java Worker',rss_kib=v*1024) for i,v in enumerate(values,1)}
            rows.append(bench.point(found,t,'build'))
        rows.append(dict(seconds=2,phase='resident',jvm_sum_kib=80*1024,daemon_max_kib=70*1024,jvm_count=1))
        s=bench.summarize_samples(rows)
        self.assertEqual(s['peak_jvm_sum_mib'],110)
        self.assertEqual(s['peak_daemon_mib'],100)
        self.assertEqual(s['resident_jvm_median_mib'],80)
    def test_detached_daemon_children_reuse_and_zombies(self):
        text='100 1 Sat Oct 17 20:00:00 2026 120 S /jdk/bin/java -Dgradlescope.owner=unique org.gradle.launcher.daemon.bootstrap.GradleDaemon\n101 100 Sat Oct 17 20:00:01 2026 20 S /jdk/bin/java Worker\n102 1 Sat Oct 17 20:00:02 2026 99 S /jdk/bin/java unrelated\n103 1 Sat Oct 17 20:00:02 2026 0 Z java\n'
        t=bench.parse_ps(text);found=bench.owned(t,'unique',set())
        self.assertEqual(set(found),{100,101});self.assertNotIn(103,t)
        known={bench.identity(t[101])}
        t[101]['ppid']=1
        self.assertIn(101,bench.owned(t,'absent',known))
        t[101]['start']='new start'
        self.assertNotIn(101,bench.owned(t,'absent',known))
        with patch('bench.os.kill') as kill:
            self.assertFalse(bench.signal_identity(dict(pid=101,start='old start'),signal.SIGTERM,t));kill.assert_not_called()
    def test_abbreviated_exit_command_keeps_jvm_and_daemon_identity(self):
        owner=bench.Owner('unique')
        live=dict(pid=99,ppid=1,start='same start',rss_kib=200,command='/jdk/bin/java -Xlog:gc:file=/tmp/gc-unique-%p.log org.gradle.launcher.daemon.bootstrap.GradleDaemon')
        exiting=dict(pid=99,ppid=1,start='same start',rss_kib=220,command='(java)')
        with patch('bench.table',side_effect=[{99:live},{99:exiting}]):
            owner.scan();found=owner.scan()
        self.assertTrue(bench.is_jvm(found[99]))
        row=bench.point(found,1,'build')
        self.assertEqual(row['jvm_sum_kib'],220)
        self.assertEqual(row['daemon_max_kib'],220)

    def test_failure_classification(self):
        self.assertEqual(bench.classify(1,'java.lang.OutOfMemoryError: Java heap space'),'java_heap_oom')
        self.assertEqual(bench.classify(-9,''),'unknown_termination')
        self.assertEqual(bench.classify(1,'',True),'timeout')
        self.assertEqual(bench.classify(1,'compile failed'),'build_error')
    def test_marker_mentions_do_not_authorize_cleanup(self):
        unrelated=dict(pid=10,ppid=1,start='now',rss_kib=20,command='/bin/python3 reader.py marker')
        fake_java=dict(pid=11,ppid=1,start='now',rss_kib=20,command='/jdk/bin/java -Ddescription=marker Main')
        quoted=dict(pid=13,ppid=1,start='now',rss_kib=20,command='/jdk/bin/java Main -Dgradlescope.owner=marker')
        prefix=dict(pid=12,ppid=1,start='now',rss_kib=20,command='/jdk/bin/java -Dgradlescope.owner=marker-other Main')
        self.assertFalse(bench.owned({p['pid']:p for p in [unrelated,fake_java,prefix,quoted]},'marker',set()))

    def test_failure_kind_survives_daemon_mismatch(self):
        full=dict(status='success',daemons=[dict(pid=1,start='old')])
        for failure in ['java_heap_oom','timeout','build_error','unknown_termination']:
            hot=dict(status=failure,daemons=[dict(pid=2,start='new')],evidence={})
            bench.validate_pair(full,hot)
            self.assertEqual(hot['status'],failure)
            self.assertFalse(hot['evidence']['same_daemon'])
            self.assertTrue(hot['validation_errors'])

    def test_cleanup_failure_is_not_confirmation(self):
        import itertools
        owner=bench.Owner('test')
        p=dict(pid=1,start='time',command='/jdk/bin/java')
        with patch.object(owner,'scan',return_value={1:p}),patch('bench.signal_identity',return_value=True),patch('bench.time.monotonic',side_effect=itertools.count(0,10)):
            with self.assertRaisesRegex(RuntimeError,'Cleanup not confirmed'):owner.cleanup()
        self.assertFalse(owner.last_cleanup['confirmed'])
        self.assertEqual(len(owner.last_cleanup['actions']),2)

    def test_cleanup_failure_does_not_erase_measurement_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);owner=bench.Owner('x')
            prepared=dict(command=['fake'],home=out,source_hash='fixture')
            with patch('bench.capture',return_value={}),patch('bench.table',return_value={}),patch('bench.subprocess.Popen') as launch,patch.object(owner,'scan',side_effect=RuntimeError('sampling failed')),patch.object(owner,'cleanup',side_effect=RuntimeError('cleanup failed')):
                launch.return_value.poll.return_value=None
                with self.assertRaisesRegex(RuntimeError,'cleanup failed'):
                    bench.measure('7.5.1','configuration',out,owner,prepared=prepared)
            result=json.loads((out/'result.json').read_text())
            self.assertEqual(result['status'],'measurement_error')
            self.assertIn('sampling failed',result['error'])
            self.assertFalse(json.loads((out/'emergency-cleanup.json').read_text())['confirmed'])

    def test_existing_output_is_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'existing';out.mkdir();(out/'interruption.json').write_text('original')
            before={p.name:p.read_bytes() for p in out.iterdir()}
            with patch('bench.ROOT',root),patch('bench.run') as run:
                with self.assertRaises(FileExistsError):bench.main(['run','--output',str(out)])
                run.assert_not_called()
            self.assertEqual(before,{p.name:p.read_bytes() for p in out.iterdir()})

    def test_lock_precedes_all_initialization(self):
        from locking import benchmark_lock
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);out=root/'new'
            with benchmark_lock(root),patch('bench.ROOT',root):
                with self.assertRaisesRegex(RuntimeError,'holds the project lock'):
                    bench.main(['run','--output',str(out)])
            self.assertFalse(out.exists())

    def test_entry_checks_prerequisites_before_self_tests_and_benchmark(self):
        # Missing tools must fail before Java-based self-tests or measurement starts.
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);events=[]
            with patch('bench.ROOT',root),patch('generate.generate',side_effect=lambda _:events.append('generate')),patch('bench.preflight',side_effect=lambda:events.append('preflight')),patch('prepare.ensure',side_effect=lambda:events.append('wrapper')),patch('bench.subprocess.run',side_effect=lambda *a,**k:events.append('tests')),patch('bench.run',side_effect=lambda _:events.append('run')),patch('bench.signal.signal'):
                bench.main(['run','--output',str(root/'new')])
            self.assertEqual(events,['generate','preflight','wrapper','tests','run'])

    def test_prior_orphan_worker_blocks_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);p=dict(pid=999,ppid=1,start='old',command='/jdk/bin/java Worker',rss_kib=2)
            bench.dump(root/'.state/owners/test.json',dict(marker='test',identities=[p]))
            with patch('bench.ROOT',root),patch('bench.table',return_value={999:p}),patch('bench.capture',return_value=dict(output='openjdk version "17.0.20.1"')):
                with self.assertRaisesRegex(RuntimeError,'Previous experiment processes'):bench.preflight()

    def test_linked_module_cannot_delete_other_project_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'project';external=Path(tmp)/'external';root.mkdir();(external/'build').mkdir(parents=True)
            sentinel=external/'build/keep';sentinel.write_text('other project')
            (root/'modules').mkdir()
            (root/'modules/lib0000').symlink_to(external,target_is_directory=True)
            with patch('bench.ROOT',root):
                with self.assertRaisesRegex(RuntimeError,'linked project path'):bench.clean_outputs()
            self.assertEqual(sentinel.read_text(),'other project')

    def test_bulk_full_finalization_waits_until_after_hot_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=dict(sha256='fixture');bench.dump(root/'fixture.json',source)
            events=[]
            full=dict(status='pending_validation',scenario='full',evidence={},daemons=[dict(pid=1,start='t')],monotonic_end=10,resident_window_end=13)
            hot=dict(status='success',scenario='hot',evidence={},daemons=[dict(pid=1,start='t')],monotonic_start=13.01)
            def measure(v,scene,out,owner,offline,prepared,deferred):
                events.append('capture-'+scene)
                if scene=='full':
                    def finish():events.append('finalize-full');full['status']='success'
                    deferred.append(finish);return full
                self.assertNotIn('finalize-full',events)
                return hot
            with patch('bench.ROOT',root),patch('bench.select'),patch('bench.fingerprint',return_value=source),patch('bench.table',return_value={}),patch('bench.clean_outputs'),patch('bench.prepare_measure',return_value=dict(jvmargs='same')),patch('bench.measure',side_effect=measure):
                bench.run_unit('7.5.1',root/'unit',['full','hot'],True)
            self.assertEqual(events,['capture-full','capture-hot','finalize-full'])

    def test_deferred_capture_persists_exit_before_bulk_finalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);owner=bench.Owner('test');pending=[]
            proc=dict(pid=99,ppid=1,start='t',rss_kib=2048,kind='daemon',command='/jdk/bin/java org.gradle.launcher.daemon.bootstrap.GradleDaemon')
            with patch('bench.capture',return_value={}),patch('bench.table',return_value={}),patch('bench.RESIDENT',0),patch.object(owner,'scan',return_value={99:proc}),patch('bench.subprocess.Popen') as launch:
                launch.return_value.poll.return_value=0;launch.return_value.returncode=0
                result=bench.measure('7.5.1','full',out,owner,prepared=dict(command=['fake'],home=out,source_hash='fixture'),deferred=pending)
            self.assertEqual(result['status'],'pending_validation')
            self.assertEqual(json.loads((out/'capture.json').read_text())['exit_code'],0)
            self.assertEqual(len(pending),1)
            self.assertFalse((out/'samples.csv').exists())
            self.assertFalse((out/'result.json').exists())

class Live(unittest.TestCase):
    def test_sigterm_controller_cleans_only_marked_java(self):
        bench.table()
        marker='gstest'+uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'Sleeper.java'
            source.write_text('class Sleeper { public static void main(String[] args) throws Exception { Thread.sleep(60000); } }')
            subprocess.run([str(bench.JDK/'bin/javac'),str(source)],check=True)
            program="""
import sys,signal,time,subprocess,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import bench
root=Path(sys.argv[2]);marker=sys.argv[3]
owner=bench.Owner(marker)
def stop(sig,frame):raise KeyboardInterrupt('SIGTERM')
signal.signal(signal.SIGTERM,stop)
child=subprocess.Popen([str(bench.JDK/'bin/java'),'-Dgradlescope.owner='+marker,'-cp',str(root),'Sleeper'])
try:
    owner.scan();(root/'ready').write_text('ready')
    while True:time.sleep(.1)
except KeyboardInterrupt:pass
finally:
    try:owner.cleanup()
    finally:
        bench.dump(root/'cleanup.json',owner.last_cleanup)
        child.wait(timeout=5)
"""
            controller=subprocess.Popen([os.sys.executable,'-c',program,str(bench.ROOT/'scripts'),tmp,marker],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                deadline=time.monotonic()+10
                while not (root/'ready').exists() and time.monotonic()<deadline:
                    if controller.poll() is not None:raise RuntimeError(controller.communicate())
                    time.sleep(.05)
                self.assertTrue((root/'ready').exists())
                controller.send_signal(signal.SIGTERM)
                output,error=controller.communicate(timeout=15)
                self.assertEqual(controller.returncode,0,error)
                self.assertTrue(json.loads((root/'cleanup.json').read_text())['confirmed'])
                self.assertFalse(bench.Owner(marker).scan())
            finally:
                if controller.poll() is None:
                    controller.terminate();controller.communicate(timeout=15)
                bench.Owner(marker).cleanup()

    def test_detached_real_java_cleanup_and_unrelated_survives(self):
        bench.table()  # Fail before creating Java processes when ps is unavailable.
        marker='gstest'+uuid.uuid4().hex
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'Sleeper.java'
            source.write_text('class Sleeper { public static void main(String[] args) throws Exception { Thread.sleep(60000); } }')
            subprocess.run([str(bench.JDK/'bin/javac'),str(source)],check=True)
            other=subprocess.Popen([str(bench.JDK/'bin/java'),'-cp',tmp,'Sleeper'])
            owner=bench.Owner(marker)
            try:
                # Shell exits immediately, leaving JVM reparented and outside launcher tree.
                subprocess.run(['sh','-c','"$1" "-Xlog:gc:file=$3/gc-$2-%p.log" -cp "$3" Sleeper >/dev/null 2>&1 &', 'sh', str(bench.JDK/'bin/java'),marker,tmp],check=True)
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    found=owner.scan()
                    if any(bench.is_jvm(p) for p in found.values()):break
                    time.sleep(.05)
                self.assertTrue(found)
                self.assertNotIn(other.pid,found)
                result=owner.cleanup()
                self.assertTrue(result['confirmed']);self.assertFalse(owner.scan())
                self.assertIsNone(other.poll())
                # Exercise exception/finally cleanup path.
                child=subprocess.Popen([str(bench.JDK/'bin/java'),'-Xlog:gc:file='+str(Path(tmp)/('gc-'+marker+'-%p.log')),'-cp',tmp,'Sleeper'])
                try:
                    time.sleep(.2);owner.scan();raise RuntimeError('simulated interruption')
                except RuntimeError:pass
                finally:owner.cleanup();child.wait(timeout=5)
                self.assertFalse(owner.scan());self.assertIsNone(other.poll())
            finally:
                try:owner.cleanup()
                finally:
                    other.terminate();other.wait(timeout=5)

if __name__=='__main__':unittest.main(verbosity=2)
