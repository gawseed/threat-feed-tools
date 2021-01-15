import unittest
from gawseed.threatfeed.datasources import DataSource, BINARY_YES, BINARY_NO, BINARY_MAYBE


class fakebinary(DataSource):
    def __init__(self, data=[{'key': 'abcd'},
                             {'key': 'abcd'}], binary=BINARY_NO):
        super().__init__({})
        self.data = data
        self._binary = binary

    def __iter__(self):
        for string in self.data:
            yield string

    def convert_row_to_utf8(self, row):
        from gawseed.threatfeed.datasources import DataSource
        return DataSource.convert_row_to_utf8(self, row)

    def encode_dict(self, item):
        from gawseed.threatfeed.datasources import DataSource
        return DataSource.encode_dict(self, item)

class test_ip_search(unittest.TestCase):
    def test_load_ip_search(self):
        import gawseed.threatfeed.search.ip
        self.assertTrue(True, "imported gawseed.threatfeed.search.ip")

        created = gawseed.threatfeed.search.ip.IPSearch({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.ip.IPSearch,
                         "created a gawseed.threatfeed.search.ip.IPSearch")

    def test_non_binary_search(self):
        "The simplistic case: do ascii search strings match ascii data"
        from gawseed.threatfeed.search.ip import IPSearch

        config = {'search_keys': ['key']}
        datasource = fakebinary()
        created = IPSearch(config, {'abcd': 'abcd'}, datasource, False)
        created.initialize()
        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, ({'key': 'abcd'}, 'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")

    def test_binary_search(self):
        "Do binary search strings match binary data?  But it returns utf-8 decoded."
        from gawseed.threatfeed.search.ip import IPSearch

        #
        # with binary keys passed in
        config = {'search_keys': [b'key']}
        datasource = fakebinary(data=[{b'key': b'abcd'},
                                      {b'key': b'abcd'}], binary=BINARY_YES)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)
        created.initialize()

        count = 0
        for match in created:
            count += 1
            # returns a DECODED row
            self.assertEqual(match, ({'key': 'abcd'}, b'abcd'),
                             "data is correct")

        self.assertEqual(count, 2, "two matches returned")

    def test_binary_data_with_nonbinary_keys(self):
        "test what happens when the data is binary, but the search data isn't"
        from gawseed.threatfeed.search.ip import IPSearch
        #
        # with ascii keys passed in -- should get converted inside for searching
        #
        config = {'search_keys': ['key']}
        datasource = fakebinary(data=[{b'key': b'abcd'},
                                      {b'key': b'abcd'}], binary=BINARY_YES)
        created = IPSearch(config, {'abcd': 'abcd'}, datasource, False)
        created.initialize()

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, ({'key': 'abcd'},
                                      'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")

    def test_non_binary_data_but_binary_search(self):
        "do binary search strings still match non-binary data"
        from gawseed.threatfeed.search.ip import IPSearch

        #
        # with ascii keys passed in -- should get converted inside for searching
        #
        config = {'search_keys': ['key']}
        datasource = fakebinary(data=[{'key': 'abcd'},
                                      {'key': 'abcd'}], binary=BINARY_NO)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)
        created.initialize()

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, ({'key': 'abcd'},
                                      b'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")

    def test_mixed_fails(self):
        "mixed binary/ascii data fails"
        from gawseed.threatfeed.search.ip import IPSearch

        config = {'search_keys': ['key']}
        datasource = fakebinary(data=[{'key': 'abcd'},
                                      {b'key': b'abcd'}], binary=BINARY_NO)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)
        created.initialize()

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, ({'key': 'abcd'},
                                      b'abcd'), "data is correct")

        self.assertEqual(count, 1, "only one match returned")

    def test_mixed_maybe(self):
        "mixed binary/ascii support with a flag"
        from gawseed.threatfeed.search.ip import IPSearch

        config = {'search_keys': ['key']}
        datasource = fakebinary(data=[{'key': 'abcd'},
                                      {b'key': b'abcd'}], binary=BINARY_MAYBE)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)
        created.initialize()

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, ({'key': 'abcd'},
                                      b'abcd'), "data is correct")

        self.assertEqual(count, 2, "only one match returned")
        
