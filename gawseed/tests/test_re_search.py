import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search.re
        self.assertTrue(True, "imported gawseed.threatfeed.search.re")

        created = gawseed.threatfeed.search.re.RESearch({'key': 'key'}, [], None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.re.RESearch,
                         "created a gawseed.threatfeed.search.re.RESearch")
        
