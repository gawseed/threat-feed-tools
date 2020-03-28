import pyfsdb
from . import DataSource

class FsdbDataSource(DataSource):
    """Loads data from a tab-separated FSDB formatted file (see pyfsdb)"""
    def __init__(self, conf):
        super().__init__(conf)
        
        self._file_handle = self.config('file_handle', datatype='file_handle',
                                        help="A python3 opened file handle for the BRO data to be streamed")
        self._file = self.config('file',
                                 help="The file name to read the bro data stream from")
        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")
        self._time_column = self.config('time_column',
                                        help="Time column to use when searching through data")

    def initialize(self):
        super().initialize()
        if not self._file_handle and not self._file:
            self.config_error("either file_handle or file is required for the %s module" % (type(self)))

    def open(self):
        self._fh = pyfsdb.Fsdb(file_handle=self._file_handle, filename=self._file,
                               return_type=pyfsdb.RETURN_AS_DICTIONARY)


        self.maybe_skip_to_time()

    def maybe_skip_to_time(self):
        if self._begin_time or self._end_time:
            self._fh_time_column = self._fh.get_column_number(self._time_column)

        if self._begin_time:
            # find the start of the data based on time
            while True:
                row = next(self)
                if float(row[self._time_column]) >= self._begin_time:
                    break

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._fh)
        if self._end_time and float(row[self._time_column]) >= self._end_time:
            raise StopIteration()
        return row

