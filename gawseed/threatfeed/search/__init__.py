from gawseed.threatfeed.config import Config

class Search(Config):
    def __init__(self, search_list, data_iterator, binary_search, conf):
        super().__init__(conf)
        self._search_list = search_list
        self._data_iterator = data_iterator
        self._binary_search = binary_search
        if binary_search:
            self.convert_to_binary_search_list()
    
    def __iter__(self):
        return self

    def __next__(self):
        for row in self._data_iterator:
            match = self.search(row)
            if match:
                if self._binary_search:
                    row = self.convert_row_to_utf8(row)
                yield (row, match)

    def convert_row_to_utf8(self, row):
        utf8_row = []
        for item in row:
            if type(item) == bytes:
                utf8_row.append(item.decode())
            else:
                utf8_row.append(item)
        return utf8_row

    def convert_to_binary_search_list(self):
        new_list = {}
        for key in self._search_list:
            # stores both new binary key and the old
            new_list[bytes(key,'utf-8')] = self._search_list[key]
            new_list[key] = self._search_list[key]
        self._search_list = new_list

    def maybe_convert_token_to_binary(self, value):
        if type(value) != str:
            return value
        if self._binary_search:
            return bytes(value, 'utf-8')
        return value

    def maybe_convert_list_to_binary(self, values):
        if not self._binary_search:
            return values

        new_list = []
        for value in values:
            new_list.append(self.maybe_convert_token_to_binary(value))
        return new_list

