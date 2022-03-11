import re
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
        self.initialize_ranges()

    def ip_to_int(self, ip):
        if ip.find(":") != -1:
            # ipv6
            return (int(ipaddress.IPv6Address(ip)), 128)
        else:
            return (int(ipaddress.IPv4Address(ip)), 32)

    def initialize_ranges(self):
        self._range_list = []
        self._left_keys = []

        # modify the lists to be ranges
        reblock = re.compile("([^/]+)/([0-9]+)$") # no netmasks currently
        for search_item in self._search_list:
            # is it a 2-column range?
            if type(search_item) == list:
                (ip_lft, mask) = self.ip_to_int(search_item[0])
                (ip_rht, mask) = self.ip_to_int(search_item[1])
                self._left_keys.append(ip_lft)
                self._range_list.append({"left": ip_lft,
                                         'right': ip_rht,
                                         'match': search_item})

            elif "-" in search_item:
                (left, right) = search_item.split("-")
                (ip_lft, mask) = self.ip_to_int(left.strip())
                (ip_rht, mask) = self.ip_to_int(right.strip())
                self._left_keys.append(ip_lft)
                self._range_list.append({"left": ip_lft,
                                         'right': ip_rht,
                                         'match': search_item})

            # or it should be a address/netmask format
            else:
                results = reblock.search(search_item)
                if results:
                    # get the mask and mask size_value for v4/v6
                    (ip, masksize) = self.ip_to_int(results.group(1))
                    mask = masksize-int(results.group(2))

                    # get the integer start/end of the range
                    ip_lft = ip - ip % (2**mask)
                    ip_rht = ip_lft + 2**mask-1

                    # save them
                    self._left_keys.append(ip_lft)
                    self._range_list.append({"left": ip_lft,
                                             'right': ip_rht,
                                             'match': search_item})
                else:
                    raise ValueError("entry %s is an unparsable range" % (search_item))
                pass

        # need to sort them into roughly the right order (overlaps dealt with later)
        self._left_keys = sorted(self._left_keys)
        self._range_list = sorted(self._range_list, key=lambda x: x['left'])
        self._length = len(self._left_keys)

    def search(self, row):
        # for each key we want to search for
        for key in self._search_keys:
            # extract the ip address for the key
            (ip, mask) = self.ip_to_int(row[key])
            # see if that address is somewhere within our list of addresses
            point = bisect(self._left_keys, ip)
            if point != 0:
                range_info = self._range_list[point-1]
                if ip < range_info['left'] or ip > range_info['right']:
                    # no match at all; we fell between ranges
                    return None

                # found a match, but see if we have a better match
                # left or right
                range_answer = range_info

                # see if we have a more exact answer
                left_point = point - 1
                if left_point < 0:
                    return range_answer
                
                range_info = self._range_list[left_point]
                while left_point >= 0 and \
                      ip >= range_info['left'] and \
                      ip <= range_info['right']:

                    # see if the new range is more narrow than current
                    if range_info['right']-range_info['left'] < \
                       range_answer['right']-range_answer['left']:
                        range_answer = range_info

                    left_point -= 1
                    range_info = self._range_list[left_point]

                # see if we have a more exact answer
                right_point = point + 1
                if right_point >= self._length:
                    return range_answer
                
                range_info = self._range_list[right_point]
                while right_point < self._length and \
                      ip >= range_info['left'] and \
                      ip <= range_info['right']:

                    # see if the new range is more narrow than current
                    if range_info['right']-range_info['left'] < \
                       range_answer['right']-range_answer['left']:
                        range_answer = range_info

                    right_point += 1
                    range_info = self._range_list[right_point]


                return range_answer

        return None

