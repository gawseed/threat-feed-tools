import unittest

class test_datasource_fsdb(unittest.TestCase):
    def test_load_datasource_fsdb(self):
        import gawseed.threatfeed.datasources.fsdb
        self.assertTrue(True, "imported gawseed.threatfeed.datasources.fsdb")

        created = gawseed.threatfeed.datasources.fsdb.FsdbDataSource({'file': 'bogus'})
        self.assertEqual(type(created),
                         gawseed.threatfeed.datasources.fsdb.FsdbDataSource,
                         "created a gawseed.threatfeed.datasources.fsdb.FsdbDataSource")
        

