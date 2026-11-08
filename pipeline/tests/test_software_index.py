"""Asset metadata cannot change ranking or include prerequisite-only CPEs."""
from pathlib import Path
import csv
import json
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import pandas as pd
from pipeline import software_index


class SoftwareIndexTests(unittest.TestCase):
    def test_vulnerable_products_and_ranges_preserve_frozen_rank(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data').mkdir()
            (root / 'artifacts/cache').mkdir(parents=True)
            ids = ['CVE-2026-2', 'CVE-2026-1']
            pd.DataFrame({'cve_id': ids, 'snapshot_month': ['2026-01']*2}).to_csv(root/'data/scoreboard_2026.csv', index=False)
            pd.DataFrame({'cve_id': ids, 'score': [.9,.8]}).to_parquet(root/'artifacts/cache/scores_2026_full.parquet', index=False)
            pd.DataFrame({'cve_id': ids, 'vendor_identity':['',''], 'product_identity':['','']}).to_csv(root/'artifacts/scores_2026_top5000.csv',index=False)
            pd.DataFrame({'cve_id':ids}).to_csv(root/'artifacts/top500.csv',index=False)
            (root/'artifacts/product_watch_2026.csv').write_text('cve_id,vendor,product\n')
            columns = ['cve_id','vendor','product','vulnerable',*software_index.FIELDS]
            with (root/'data/affected_products.csv').open('w') as stream:
                writer=csv.DictWriter(stream,fieldnames=columns);writer.writeheader()
                writer.writerow({'cve_id':ids[1],'vendor':'example','product':'widget','vulnerable':'Y','version_end_excluding':'2.0'})
                writer.writerow({'cve_id':ids[0],'vendor':'platform','product':'os','vulnerable':'N'})
                writer.writerow({'cve_id':'CVE-2025-99','vendor':'old','product':'widget','vulnerable':'Y'})
            with patch.object(software_index,'ROOT',root):
                result=software_index.build()
                self.assertEqual(json.dumps(result),json.dumps(software_index.build()))
            self.assertEqual(result['coverage']['cpe_cves'],1)
            self.assertEqual(result['cves'],[[ids[1],2,.8,'2026-01']])
            self.assertEqual(result['products'][0]['affected'],[[0,0]])
            self.assertEqual(result['ranges'][0][-1],'2.0')
            self.assertEqual(len(result['products']),1)


if __name__ == '__main__':
    unittest.main()
