from gawseed.threatfeed.search import Search
from gawseed.threatfeed.datasources import BINARY_MAYBE


class KeysSearch(Search):
    """Searches for keys from multiple search_keys fields"""

    def __init__(self, conf, search_list, data_iterator, binary_search,
                 default_keys=['id_orig_h', 'id_resp_h']):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self._search_keys = self.config('search_keys', default_keys,
                                        help="A list of fields to search " +
                                        "for matches in the data stream")

    def initialize(self):
        super().initialize()
        self._search_keys = self._data_iterator.encode_or_decode_list(self._search_keys)
        self._data_iterator.set_hints(self._search_keys, self._search_list)

    def search(self, row):
        if self._data_iterator.is_binary() == BINARY_MAYBE:
            # we'll just (expensively) convert everything
            row = self._data_iterator.decode_dict(row)
        for key in self._search_keys:
            if key not in row:
                continue
            if row[key] in self._search_list:
                return self._search_list[row[key]]
        return None

