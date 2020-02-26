import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search
        self.assertTrue(True, "imported gawseed.threatfeed.search")

        created = gawseed.threatfeed.search.Search({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.Search,
                         "created a gawseed.threatfeed.search.Search")
        
