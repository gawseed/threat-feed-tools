import ipaddress
from bisect import bisect

from gawseed.threatfeed.search.ip import IPSearch

class IPRangeSearch(IPSearch):
    """Searches for IP address range threats in multiple search_keys fields"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self._search_keys = self.config('search_keys', ['id_orig_h', 'id_resp_h'],
                                        help="A list of fields to search for IP addresses in the data stream")

    def initialize(self):
        super().initialize()
        self._initialize_ranges()

    def initialize_ranges(self):
        self._range_list = []
        self._left_keys = []

        # modify the lists to be ranges
        for search_item in self._search_list:
            if type(search_item) == list:
                ip_lft = int(ipaddress.IPv4Address(search_item[0]))
                ip_rht = int(ipaddress.IPv4Address(search_item[1]))
                self._left_keys.append(ip_lft)
                self._range_list.append({"left": ip_lft,
                                         'right': ip_rht,
                                         'match': search_item})

            else:
                # XXX: deal with /masking
                pass

        self._left_keys = sorted(self._left_keys)
        self._range_list = sorted(self._range_list, key=lambda x: x['left'])
        self._length = len(self._left_keys)

    def search(self, row):
        # for each key we want to search for
        for key in self._search_keys:
            # extract the ip address for the key
            ip = int(ipaddress.IPv4Address(row[key]))
            # see if that address is somewhere within our list of addresses
            point = bisect(self._left_keys, ip)
            if point != 0:
                range_info = self._range_list[point-1]
                if ip >= range_info['left'] and ip <= range_info['right']:
                    # found a match, return the match info
                    return range_info['match']

        return None

