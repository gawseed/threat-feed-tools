import sys
import re

from gawseed.threatfeed.search import Search


class RESearch(Search):
    """A base class for regular expression based search engines to reuse
       functions from `search_items` should be a list regular expressions,
       and will be built into self._relist as
       {'match': item, 're': compiled_version }"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self.require(['key'])
        self._key = self.config('key', help="The key field to match against " +
                                "in the data stream")

        self._search_list = search_list
        self._data_iterator = data_iterator
        self._binary_search = binary_search

    def initialize(self):
        super().initialize()
        self._relist = []
        for item in self._search_list:
            try:
                compiled = re.compile(self._data_iterator.decode_item(item))
                self._relist.append({'match': self._search_list[item],
                                     're': compiled})
            except Exception:
                sys.stderr.write("failed to compile regular expression: %s\n" %
                                 (item))

    def search(self, row):
        """If the `source` value matches any stored expression,
           the expression will be returned."""
        # we must always convert a binary to a string in order to regexp
        return self.search_one(self._data_iterator.decode_item(row[self._key]))

    def search_one(self, source):
        """If the `source` value matches any stored expression,
           the expression will be returned."""
        if source is None:
            return
        for expr in self._relist:
            match = expr['re'].match(source)
            if match:
                return expr['match']

