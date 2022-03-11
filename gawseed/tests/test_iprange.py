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
                        'id_resp_h': '1.2.3.5',
                        'match': None},
                       # ip_orig matches the second narrow one
                       {'id_orig_h': '3.3.3.4',
                        'id_resp_h': '3.3.9.9',
                        'match': 1},
                       # ip_orig should match the third really narrow one
                       {'id_orig_h': '3.3.3.129',
                        'id_resp_h': '99.99.99.99',
                        'match': 2},
                       {'id_orig_h': '2.2.2.2', # ip_resp matches the second
                        'id_resp_h': '3.3.3.9',
                        'match': 1},
                       {'id_orig_h': '4.4.4.4',
                        'id_resp_h': '4.4.4.5',
                        'match': None},
                       {'id_orig_h': '10.0.0.1',
                        'id_resp_h': '10.0.0.2',
                        'match': None},
                       {'id_orig_h': '3.3.3.9', # should match a later but enclosing
                        'id_resp_h': '3.3.3.10',
                        'match': 1},
                       {'id_orig_h': '3.3.2.255', # should match the first
                        'id_resp_h': '99.99.99.99',
                        'match': 0},
                       {'id_orig_h': '::127',
                        'id_resp_h': '2001::1',
                        'match': 6},
                       {'id_orig_h': '::127',
                        'id_resp_h': '2002::16',
                        'match': 7},
        ]

        search_list = [['3.1.0.0', '3.3.3.6'],
                       '3.3.3.0/24',
                       '3.3.3.128/31',
                       '1.2.3.1-1.2.3.3',
                       '4.4.5.0/24',
                       '2001::0/16',
                       '2001::0/18',
                       ['2002::1', '2002::128'],
                       ['9.9.9.9', '9.9.9.10'],
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
                self.assertTrue('match' in item and item['match'] is not None,
                                "\nitem\n    {item}\n  matched\n    {result}\n  and shouldn't have matched anything".format(item=item, result=result))
                self.assertTrue(result['match'] == search_list[item['match']],
                                "\nitem\n    '{item}\n  matched\n    {result}\n  did not match item #{match}\n    ({shouldhave})\n".format(match=item['match'], result=result, item=item, shouldhave=search_list[item['match']]))
            
        self.assertEqual(count, 6,
                         "Should have two results")

if __name__ == "__main__":
    unittest.main()
    
