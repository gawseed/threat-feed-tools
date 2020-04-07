from gawseed.threatfeed.config import Config

class DataSource(Config):
    def __init__(self, conf):
        super().__init__(conf)

        self._binary = self.config("binary", self.default_is_binary(),
                                   help="If the datasource is binary (bytes) data, set this to convert when necessary")

    def initialize(self):
        super().initialize()

    def default_is_binary(self):
        return False

    def is_binary(self):
        return self._binary

    def convert_row_to_utf8(self, row):
        if not self._binary:
            return row
            
        utf8_row = {}
        for item in row:
            utf8_row[self.decode_item(item)] = self.decode_item(row[item])
        return utf8_row

    def encode_item(self, item):
        """converts a string item to a utf-8 bytes version of it"""

        # don't encode if not needed
        if not self._binary:
            return item

        if type(item) == bytes:
            return item
        return bytes(item, 'utf-8')

    def decode_item(self, item):
        """Decodes a bytes object into a utf-8 string"""

        # don't decode if not needed
        if not self._binary:
            return item

        if type(item) == bytes:
            return item.decode()

        if type(item) == list:
            return self.decode_list(item) 

        return item

    def encode_dict(self, old_dict):
        """Creates a new dict that contains both binary and string based indexes for all entries"""

        # don't encode if not needed
        if not self._binary:
            return old_dict

        new_dict = {}
        for key in old_dict:
            # stores both new binary key and the old
            new_dict[self.encode_item(key)] = old_dict[key]
            new_dict[key] = old_dict[key]
        return new_dict

    def encode_list(self, old_list):
        """Creates a new  list converted to binary if necessary"""

        # don't encode if not needed
        if not self._binary:
            return old_list

        new_list = []
        for key in old_list:
            # stores both new binary key and the old
            new_list.append(self.encode_item(key))
        return new_list

    def decode_list(self, old_list):
        new_list = []
        for key in old_list:
            # stores both new binary key and the old
            new_list.append(self.decode_item(key))
        return new_list

    def maybe_convert_token_to_binary(self, value):
        # don't encode if not needed
        if not self._binary:
            return value

        if type(value) != str:
            return value
        if self._binary_search:
            return bytes(value, 'utf-8')
        return value

    def maybe_convert_list_to_binary(self, values):
        # don't encode if not needed
        if not self._binary:
            return values

        new_list = []
        for value in values:
            new_list.append(self.maybe_convert_token_to_binary(value))
        return new_list
    
    def set_hints(self, keynames, hint_dict):
        """Sets a set of hints for things to look for; datasources that can
        more easily sub-select can use these hints to refine their
        data retrieval.  Datasources that can not will simply ignore
        the hints, and thus searchers should double check the
        results.
        """
        pass
