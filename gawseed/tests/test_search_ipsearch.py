import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search.ipsearch
        self.assertTrue(True, "imported gawseed.threatfeed.search.ipsearch")

        created = gawseed.threatfeed.search.ipsearch.IPSearch(None, None)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.ipsearch.IPSearch,
                         "created a gawseed.threatfeed.search.ipsearch.IPSearch")
        
