import unittest
from io import StringIO

class test_datasource_json(unittest.TestCase):
    def test_load_datasource_bro(self):
        import gawseed.threatfeed.datasources.json
        self.assertTrue(True, "imported gawseed.threatfeed.datasources.json")

        created = gawseed.threatfeed.datasources.json.JsonDataSource({'file': 'bogus.json'})
        self.assertEqual(type(created),
                         gawseed.threatfeed.datasources.json.JsonDataSource,
                         "created a gawseed.threatfeed.datasources.json.JsonDataSource")
        
        data = '{ "ts": "2019-01-01", "id_orig_h": "10.0.0.1"}'
        
        fh = StringIO(data)
        
        created = gawseed.threatfeed.datasources.json.JsonDataSource({'file_handle': fh})
        result = next(created)
        self.assertEqual(result, { 'ts': '2019-01-01', 'id_orig_h': '10.0.0.1'})
