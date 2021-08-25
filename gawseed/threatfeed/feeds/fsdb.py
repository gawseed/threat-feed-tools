import io
import pyfsdb
from gawseed.threatfeed.feeds import ThreatFeed

class FsdbThreatFeed(ThreatFeed):
    """Loads a threat data list from a 'key' column in a FSDB formatted file (see pyfsdb)1"""
    def __init__(self, config):
        super().__init__(config)
        self.require(['file', 'key'])
        self._fsdb_file = self.config('file',
                                      help="The file name (or URL) to read the bro data stream from")

    def open(self):
        if (self._fsdb_file.startswith("http:") or
            self._fsdb_file.startswith("https:")):
            fetched = self.geturl(self._fsdb_file).decode()
            self._file_handle = io.StringIO(fetched)
            self._tfh = pyfsdb.Fsdb(file_handle=self._file_handle,
                                    return_type=pyfsdb.RETURN_AS_DICTIONARY)
        else:
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

    def next_row(self):
        return next(self._tfh)

    def column_names(self):
        return self._tfh.column_names

    def index_column_number(self):
        return self._tfh.get_column_number(self._value_column)

    def read(self, max_records = None):
        array = []
        dictionary = {}
        for (count,entry) in enumerate(self._tfh):

            if self.drop_or_prioritize(entry, self._value_column,
                                       self._tag_column):
                continue

            array.append(entry)
            dictionary[entry[self._value_column]] = entry # note, may erase older ones; build array?
            if max_records and count+1 >= max_records:
                break

        return (array, dictionary)

        
