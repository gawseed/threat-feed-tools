import unittest


class fakedata():
    def __init__(self):
        self.data = range(30)

    def __iter__(self):
        for num in self.data:
            yield num

    def convert_row_to_utf8(self, row):
        return row


def fake_search(row):
    if row == 10:
        return 10
    return False


def fake_true(row):
    return row


class fakebinary():
    def __init__(self):
        self.data = ['abcd', b'abcd']
        self._binary = False

    def __iter__(self):
        for string in self.data:
            yield string

    def convert_row_to_utf8(self, row):
        from gawseed.threatfeed.datasources import DataSource
        DataSource.convert_row_to_utf8(self, row)



class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search
        self.assertTrue(True, "imported gawseed.threatfeed.search")

        created = gawseed.threatfeed.search.Search({}, None, None, False)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.Search,
                         "created a gawseed.threatfeed.search.Search")

    def test_searcher(self):
        import collections
        import gawseed.threatfeed.search
        created = gawseed.threatfeed.search.Search({}, [4242],
                                                   fakedata(), False)
        created.search = fake_search
        for match in created:
            self.assertEqual(match, (10, 10), "match was true")
        self.assertTrue(isinstance(created, collections.Iterable), "is type")
        self.assertTrue(True, "got end of searching")

    def test_binary(self):
        import collections
        import gawseed.threatfeed.search
        created = gawseed.threatfeed.search.Search({}, [4242],
                                                   fakebinary(), False)
        created.search = fake_true

        matches = []
        for match in created:
            matches.append(match)

        self.assertEqual(matches[0], (None, 'abcd'), "ascii was true")
        self.assertEqual(matches[1], (None, b'abcd'), "binary was true")

        self.assertTrue(True, "got end of searching")

    def test_status_queue(self):
        import gawseed.threatfeed.search
        import queue

        status_queue = queue.Queue()
        created = gawseed.threatfeed.search.Search({}, [4242],
                                                   fakedata(), False,
                                                   status_queue,
                                                   20)
        created.search = fake_search

        for match in created:
            self.assertEqual(match, (10,10), "match was true")
        self.assertTrue(True, "got end of searching")

        result = status_queue.get()
        self.assertEqual(result,
                         {'type': 'searcher',
                          'subtype': 'counter',
                          'count': 0})

        result = status_queue.get()
        self.assertEqual(result,
                         {'type': 'searcher',
                          'subtype': 'counter',
                          'count': 20})
