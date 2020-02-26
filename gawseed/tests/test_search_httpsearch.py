import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search.http
        self.assertTrue(True, "imported gawseed.threatfeed.search.http")

        created = gawseed.threatfeed.search.http.HTTPSearch({'key': 'key'}, [], None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.http.HTTPSearch,
                         "created a gawseed.threatfeed.search.http.HTTPSearch")
        
