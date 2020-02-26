import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search.ip
        self.assertTrue(True, "imported gawseed.threatfeed.search.ip")

        created = gawseed.threatfeed.search.ip.IPSearch({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.ip.IPSearch,
                         "created a gawseed.threatfeed.search.ip.IPSearch")
        
