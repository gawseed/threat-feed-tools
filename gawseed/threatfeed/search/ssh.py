from gawseed.threatfeed.search.ip import IPSearch

class SSHSearch(IPSearch):
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        
        super().__init__(search_list, data_iterator, binary_search, conf)
        # Really need a tri-nary option for this

        auth_success_key = self.config('authsuccesskey', 'auth_success')
        auth_success_value = self.config('authsuccessvalue', True)

        self._auth_success_key = self.maybe_convert_to_binary(auth_success_key)
        self._auth_success_value = self.maybe_convert_to_binary(auth_success_value)
    
    def search(self, row):
        if not self._auth_success_key or self._auth_success_key not in row:
            return None
        if row[self._auth_success_key] != self._auth_success_value:
            return None
        return super().search(row)

