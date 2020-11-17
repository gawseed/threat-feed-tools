from gawseed.threatfeed.search.re import RESearch


class DNSSearch(RESearch):
    """Searches for a threat regexp in DNS query logs"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self._key = self.config('key', 'query',
                                help="The key of the field in the data " +
                                "stream to search for matches")  # assumes bro

    def initialize(self):
        super().initialize()
        self._key = self._data_iterator.encode_item(self._key)
