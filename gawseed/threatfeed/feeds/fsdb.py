import pyfsdb
from gawseed.threatfeed.config import Config

class FsdbThreatFeed(Config):
    """Loads a threat data list from a 'key' column in a FSDB formatted file (see pyfsdb)1"""
    def __init__(self, config):
        super().__init__(config)
        self.require(['file', 'key'])
        self._fsdb_file = self.config('file',
                                      help="The file name to read the bro data stream from")
        self._value_column = self.config('key',
                                         help="The column name to use for pulling threat data")

        self._time_column = self.config('time_column',
                                        help="Time column to use when searching through data")
        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")

    def open(self):
        self._tfh = pyfsdb.Fsdb(self._fsdb_file,
                                return_type=pyfsdb.RETURN_AS_DICTIONARY)
        self._tfh_index_column = self._tfh.get_column_number(self._value_column)

        if self._begin_time or self._end_time:
            self._tfh_time_column = self._tfh.get_column_number(self._time_column)

        if self._begin_time:
            # find the start of the data based on time
            while True:
                row = next(self)
                if row[self._tfh_time_column] >= self._begin_time:
                    break

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._tfh)
        if self._end_time and row[self._tfh_time_column] >= self._end_time:
            raise StopIteration()
        return row

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

        
