from gawseed.threatfeed.search import Search

class IPSearch(Search):
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        super().__init__(search_list, data_iterator, binary_search, conf)
        search_keys = self.config('searchkeys', ['id_orig_h', 'id_resp_h'])
        self._search_keys = self.maybe_convert_binary_list(search_keys)
    
    def search(self, row):
        for key in self._search_keys:
            if row[key] in self._search_list:
                return self._search_list[row[key]]
        return None

