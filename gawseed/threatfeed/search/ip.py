from gawseed.threatfeed.search import Search

class IPSearch(Search):
    """Searches for IP address threats in multiple search_keys fields"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self._search_keys = self.config('search_keys', ['id_orig_h', 'id_resp_h'],
                                        help="A list of fields to search for IP addresses in the data stream")

    def initialize(self):
        super().initialize()
        self._search_keys = self._data_iterator.encode_list(self._search_keys)
        self._data_iterator.set_hints(self._search_keys, self._search_list)
    
    def search(self, row):
        for key in self._search_keys:
            if row[key] in self._search_list:
                return self._search_list[row[key]]
        return None

