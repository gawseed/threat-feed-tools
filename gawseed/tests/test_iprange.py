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
                       {'id_orig_h': '3.3.3.4', # ip_orig matches the first item
                        'id_resp_h': '3.3.9.9'},
                       {'id_orig_h': '2.2.2.2', # ip_resp matches the second
                        'id_resp_h': '3.3.3.9'},
                       {'id_orig_h': '4.4.4.4',
                        'id_resp_h': '4.4.4.5'},
        ]
        search_list = [['3.1.0.0', '3.3.3.6'],
                       '3.3.3.0/24',
                       ['1.2.3.1', '1.2.3.3'],
                       '4.4.5.0/24',
                       ['9.9.9.9', '9.9.9.10']
        ]

        searcher = gawseed.threatfeed.search.iprange.IPRangeSearch({}, search_list,
                                                                  data_source,
                                                                  False)
        self.assertEqual(type(searcher),
                         gawseed.threatfeed.search.iprange.IPRangeSearch,
                         "searcher a gawseed.threatfeed.search.iprange.IPRangeSearch")
        searcher.initialize_ranges()
        self.assertTrue(True, 'initialized ok')

        count = 0
        for item in data_source:
            result = searcher.search(item)
            if result:
                count += 1
                self.assertTrue(result == search_list[0] or
                                result == search_list[1],
                                "search list match was correct")
            
        self.assertEqual(count, 2,
                         "Should have two results")

if __name__ == "__main__":
    unittest.main()
    
