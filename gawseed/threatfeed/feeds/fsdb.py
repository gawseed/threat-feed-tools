import pyfsdb

class FsdbThreatFeed():
    def __init__(self, fsdb_file=None, value_column="ip"):
        self._fsdb_file = fsdb_file
        self._value_column = value_column

    def open(self):
        self._tfh = pyfsdb.Fsdb(self._fsdb_file)
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
        index_column = self.index_column_number()
        for (count,entry) in enumerate(self._tfh):
            array.append(entry)
            dictionary[entry[index_column]] = entry # note, may erase older ones; build array?
            if max_records and count+1 >= max_records:
                break

        return (array, dictionary)

        
