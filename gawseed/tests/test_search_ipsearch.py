import unittest
from gawseed.threatfeed.datasources import DataSource, \
    BINARY_YES, BINARY_NO, BINARY_MAYBE


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
        DataSource.convert_row_to_utf8(self, row)


class test_ip_search(unittest.TestCase):
    def test_load_ip_search(self):
        import gawseed.threatfeed.search.ip
        self.assertTrue(True, "imported gawseed.threatfeed.search.ip")

        created = gawseed.threatfeed.search.ip.IPSearch({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.ip.IPSearch,
                         "created a gawseed.threatfeed.search.ip.IPSearch")

    def test_non_binary_search(self):
        from gawseed.threatfeed.search.ip import IPSearch

        config = {'search_keys': ['key']}
        datasource = fakebinary()
        created = IPSearch(config, {'abcd': 'abcd'}, datasource, False)

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, (None, 'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")

    def test_binary_search(self):
        from gawseed.threatfeed.search.ip import IPSearch

        #
        # with non binary keys
        config = {'search_keys': ['key']}
        datasource = fakebinary(data=[{'key': b'abcd'},
                                      {'key': b'abcd'}], binary=BINARY_YES)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, (None, b'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")

        #
        # with binary keys
        config = {'search_keys': [b'key']}
        datasource = fakebinary(data=[{b'key': b'abcd'},
                                      {b'key': b'abcd'}], binary=BINARY_YES)
        created = IPSearch(config, {b'abcd': b'abcd'}, datasource, False)

        count = 0
        for match in created:
            count += 1
            self.assertEqual(match, (None, b'abcd'), "data is correct")

        self.assertEqual(count, 2, "two matches returned")
        
