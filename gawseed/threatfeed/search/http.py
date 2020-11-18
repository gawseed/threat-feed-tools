from gawseed.threatfeed.search.re import RESearch


class HTTPSearch(RESearch):
    """Matches a regexp threat against a host/uri combo data field
    (aka bro log)"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)

        self._host_key = self.config('host_key', 'host',
                                     help="The column name for the host to " +
                                     "construct a URL out of")

        self._uri_key = self.config('uri_key', 'uri',
                                    help="The column name for the uri " +
                                    "portion of the URL")

    def initialize(self):
        super().initialize()

    def search(self, row):
        # XXX: currently assumes a split host/uri scheme like bro.
        # Need to make this generic
        if self._host_key not in row or \
           self._uri_key not in row or row[self._host_key] is None or \
           row[self._uri_key] is None:
            return None

        host = self._data_iterator.decode_item(row[self._host_key])
        uri = self._data_iterator.decode_item(row[self._uri_key])

        url = "http://" + host + "/" + uri

        return self.search_one(url)

