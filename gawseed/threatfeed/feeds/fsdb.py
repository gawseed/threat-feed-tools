import pyfsdb

class FsdbThreatFeed():
    def __init__(self, fsdb_file=None, value_column="value"):
        self._fsdb_file = fsdb_file
        self._value_column = value_column

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

        
