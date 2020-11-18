from gawseed.threatfeed.search.keys import KeysSearch
from gawseed.threatfeed.datasources import BINARY_MAYBE


class IPSearch(KeysSearch):
    "Searches for IP address threats in multiple search_keys fields"
    def __init__(self, conf, search_list, data_iterator, binary_search):
        # really this is just a wrapper around id_orig_h and id_resp_h bro keys
        super().__init__(conf, search_list, data_iterator, binary_search,
                         ['id_orig_h', 'id_resp_h'])
