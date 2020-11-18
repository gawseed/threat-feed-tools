from gawseed.threatfeed.search.ip import IPSearch

class SSHSearch(IPSearch):
    """Searches data for threats, but requires the auth_success field to
    be True. IE, only successful logins will be considered a match.
    Use the 'ip' module if you don't want this restriction applied."""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        
        super().__init__(conf, search_list, data_iterator, binary_search)
        # Really need a tri-nary option for this

        self._auth_success_key = self.config('auth_success_key', 'auth_success',
                                             help="When searching for authenticated ssh connections, use this column name to determine if authentication suceeded")
        self._auth_success_value = self.config('auth_success_value', True,
                                               help="The value that should match the authentication field identified by auth_success_key")

    def initialize(self):
        super().initialize()
        self._auth_success_key = self._data_iterator.encode_item(self._auth_success_key)
        if type(self._auth_success_value) == str:
            self._auth_success_value = self._data_iterator.encode_item(self._auth_success_value)
    
    def search(self, row):
        if not self._auth_success_key or self._auth_success_key not in row:
            return None
        if row[self._auth_success_key] != self._auth_success_value:
            return None
        return super().search(row)  # pass the rest to the IP searcher

