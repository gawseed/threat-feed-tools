import unittest

class testiprange(unittest.TestCase):
    def test_iprange_load(self):
        import gawseed.threatfeed.search.iprange
        self.assertTrue(True, "loaded iprange successfully")

        created = gawseed.threatfeed.search.iprange.IPRangeSearch({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.iprange.IPRangeSearch,
                         "created a gawseed.threatfeed.search.iprange.IPRangeSearch")

    def test_iprange_works(self):
        import gawseed.threatfeed.search.iprange

        # fake some data
        data_source = [{'id_orig_h': '1.2.3.4',
                        'id_resp_h': '1.2.3.5'},
                       {'id_orig_h': '3.3.3.4',
                        'id_resp_h': '3.3.3.5'},
                       {'id_orig_h': '4.4.4.4',
                        'id_resp_h': '4.4.4.5'},
        ]
        search_list = [['3.1.0.0', '3.3.3.6']]

        searcher = gawseed.threatfeed.search.iprange.IPRangeSearch({}, search_list,
                                                                  data_source,
                                                                  False)
        self.assertEqual(type(searcher),
                         gawseed.threatfeed.search.iprange.IPRangeSearch,
                         "searcher a gawseed.threatfeed.search.iprange.IPRangeSearch")
        searcher.initialize_ranges()
        self.assertTrue(True, 'initialized ok')

        for item in data_source:
            result = searcher.search(item)
            if result:
                self.assertEqual(result, search_list[0])
            
