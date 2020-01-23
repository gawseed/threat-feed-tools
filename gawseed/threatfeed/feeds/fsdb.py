import pyfsdb
from gawseed.threatfeed.config import Config

class FsdbThreatFeed(Config):
    """Loads a threat data list from a 'key' column in a FSDB formatted file (see pyfsdb)"""
    def __init__(self, config):
        super().__init__(config)
        self.require(['file', 'key'])
        self._fsdb_file = self.config('file',
                                      help="The file name to read the bro data stream from")
        self._value_column = self.config('key',
                                         help="The column name to use for pulling threat data")

    def open(self):
        self._tfh = pyfsdb.Fsdb(self._fsdb_file,
                                return_type=pyfsdb.RETURN_AS_DICTIONARY)
        self._tfh_index_column = self._tfh.get_column_number(self._value_column)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._tfh)

    def column_names(self):
        return self._tfh.column_names

    def index_column_number(self):
        return self._tfh.get_column_number(self._value_column)

    def read(self, max_records = None):
        array = []
        dictionary = {}
        for (count,entry) in enumerate(self._tfh):
            array.append(entry)
            dictionary[entry[self._value_column]] = entry # note, may erase older ones; build array?
            if max_records and count+1 >= max_records:
                break

        return (array, dictionary)

        
