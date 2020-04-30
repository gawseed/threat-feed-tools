import unittest
from io import StringIO

class test_datasource_excluding(unittest.TestCase):
    def test_load_datasource_fsdb(self):
        import gawseed.threatfeed.datasources.fsdb
        self.assertTrue(True, "imported gawseed.threatfeed.datasources.fsdb")

        data = StringIO("#fsdb -F t key value\na\t1\nb\t2\nc\t3\n")

        created = gawseed.threatfeed.datasources.fsdb.FsdbDataSource({'file_handle': data})
        created.open()

        results = []
        for row in created:
            results.append(row)

        self.assertEqual(results,
                         [{'key': 'a', 'value': '1'},
                          {'key': 'b', 'value': '2'},
                          {'key': 'c', 'value': '3'}],
                         "data return from a straight read was good")

        # Now try it again with filtering
        data = StringIO("#fsdb -F t key value\na\t1\nb\t2\nc\t3\n")
        created = gawseed.threatfeed.datasources.fsdb.FsdbDataSource({'file_handle': data,
                                                                      'exclude_key': 'key',
                                                                      'exclude': ['b']})
        created.open()
        
        results = []
        for row in created:
            results.append(row)

        self.assertEqual(results,
                         [{'key': 'a', 'value': '1'},
                          {'key': 'c', 'value': '3'}],
                         "data return from a filtered read was good")
