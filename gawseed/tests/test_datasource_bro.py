import unittest

class test_datasource_bro(unittest.TestCase):
    def test_load_datasource_bro(self):
        import gawseed.threatfeed.datasources.bro
        self.assertTrue(True, "imported gawseed.threatfeed.datasources.bro")

        created = gawseed.threatfeed.datasources.bro.BroDataSource()
        self.assertEqual(type(created),
                         gawseed.threatfeed.datasources.bro.BroDataSource,
                         "created a gawseed.threatfeed.datasources.bro.BroDataSource")
        

