from gawseed.threatfeed.config import Config

class Search(Config):
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf)
        self._search_list = search_list
        self._data_iterator = data_iterator
        self._binary_search = binary_search

    def initialize(self):
        self._search_list = self._data_iterator.encode_dict(self._search_list)
    
    def __iter__(self):
        return self

    def __next__(self):
        for row in self._data_iterator:
            match = self.search(row)
            if match:
                row = self._data_iterator.convert_row_to_utf8(row)
                self.verbose("search hit: " + str(row))
                yield (row, match)


        
