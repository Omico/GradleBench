#!/usr/bin/env python3
"""Semantic corruption must fail even with a matching CSV manifest."""
import contextlib,csv,hashlib,io,shutil,tempfile,unittest
from pathlib import Path
import verify_csv


class VerifyCSV(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'data'
        shutil.copytree(Path(__file__).resolve().parents[1]/'data',self.root)

    def rewrite(self,name,mutate):
        path=self.root/name
        with path.open(newline='',encoding='utf-8') as stream:
            reader=csv.DictReader(stream);fields=reader.fieldnames;records=list(reader)
        with path.open('w',newline='',encoding='utf-8') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(mutate(records))

    def verify(self):
        # Refresh integrity metadata so these tests exercise semantic checks.
        def refresh(records):
            updated=[]
            for record in records:
                path=self.root/record['path']
                if not path.exists():continue
                record.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(),bytes=path.stat().st_size,rows=len(verify_csv.rows(path)))
                updated.append(record)
            return updated
        self.rewrite('manifest.csv',refresh)
        with contextlib.redirect_stdout(io.StringIO()):verify_csv.verify(self.root)

    def test_archived_dataset_passes(self):
        self.verify()

    def test_duplicate_or_missing_comparison_is_rejected(self):
        original=(self.root/'comparison.csv').read_bytes()
        for mutate in [lambda rows:rows[:-1]+[rows[0]],lambda rows:rows[:-1]]:
            with self.subTest(mutate=mutate):
                (self.root/'comparison.csv').write_bytes(original)
                self.rewrite('comparison.csv',mutate)
                with self.assertRaisesRegex(ValueError,'Comparison coverage mismatch'):self.verify()

    def test_missing_cleanup_file_is_rejected(self):
        (self.root/'cleanup.csv').unlink()
        with self.assertRaisesRegex(ValueError,'Missing cleanup records'):self.verify()

    def test_cleanup_must_cover_each_unit_once(self):
        original=(self.root/'cleanup.csv').read_bytes()
        cases={'empty':lambda rows:[], 'missing':lambda rows:rows[:-1],
               'duplicate':lambda rows:rows[:-1]+[rows[0]],
               'unrelated':lambda rows:rows[:-1]+[dict(rows[-1],unit_id='formal/09-7.5.1/full')]}
        for name,mutate in cases.items():
            with self.subTest(case=name):
                (self.root/'cleanup.csv').write_bytes(original)
                self.rewrite('cleanup.csv',mutate)
                with self.assertRaisesRegex(ValueError,'Cleanup coverage mismatch'):self.verify()

    def test_unconfirmed_or_remaining_processes_are_rejected(self):
        original=(self.root/'cleanup.csv').read_bytes()
        for values in [dict(confirmed='false'),dict(remaining_count='1')]:
            with self.subTest(values=values):
                (self.root/'cleanup.csv').write_bytes(original)
                self.rewrite('cleanup.csv',lambda rows:[dict(rows[0],**values)]+rows[1:])
                with self.assertRaisesRegex(ValueError,'Unconfirmed cleanup'):self.verify()

    def test_measurement_must_belong_to_its_round_unit(self):
        # Mutate both stages and every reference; RSS consistency alone must not
        # authorize linking this round to a different cleanup unit.
        for name in ['measurements.csv','samples.csv','rss.csv','processes.csv','heap.csv','pressure.csv','commands.csv','context.csv']:
            self.rewrite(name,lambda rows:[dict(row,measurement_id=row['measurement_id'].replace('formal/01-7.5.1/','formal/99-7.5.1/')) for row in rows])
        with self.assertRaisesRegex(ValueError,'Measurement unit mismatch'):self.verify()


if __name__=='__main__':unittest.main(verbosity=2)
