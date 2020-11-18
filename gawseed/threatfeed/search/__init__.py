from gawseed.threatfeed.config import Config


class Search(Config):
    def __init__(self, conf, search_list, data_iterator, binary_search,
                 status_queue=None, report_every=10000):
        super().__init__(conf)
        self._search_list = search_list
        self._data_iterator = data_iterator
        self._binary_search = binary_search
        self._status_queue = status_queue
        self._counter_threshold = report_every

    def initialize(self):
        self._search_list = \
            self._data_iterator.encode_or_decode_dict(self._search_list)

    def __iter__(self):
        for (n, row) in enumerate(self._data_iterator):
            match = self.search(row)
            if match:
                row = self._data_iterator.convert_row_to_utf8(row)
                yield (row, match)

            # report our status if asked
            if self._status_queue and n % self._counter_threshold == 0:
                self._status_queue.put({'type': 'searcher',
                                        'subtype': 'counter',
                                        'count': n})
