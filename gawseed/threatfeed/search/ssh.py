from gawseed.threatfeed.search.ip import IPSearch

class SSHSearch(IPSearch):
    """Searches data for threats, but requires the auth_success field to
    be True. IE, only successful logins will be considered a match.
    Use the 'ip' module if you don't want this restriction applied."""
    def __init__(self, search_list, data_iterator, binary_search, conf={}):
        
        super().__init__(search_list, data_iterator, binary_search, conf)
        # Really need a tri-nary option for this

        auth_success_key = self.config('auth_success_key', 'auth_success',
                                       help="When searching for authenticated ssh connections, use this column name to determine if authentication suceeded")
        auth_success_value = self.config('auth_success_value', True,
                                         help="The value that should match the authentication field identified by auth_success_key")

        self._auth_success_key = self.maybe_convert_to_binary(auth_success_key)
        self._auth_success_value = self.maybe_convert_to_binary(auth_success_value)
    
    def search(self, row):
        if not self._auth_success_key or self._auth_success_key not in row:
            return None
        if row[self._auth_success_key] != self._auth_success_value:
            return None
        return super().search(row)

