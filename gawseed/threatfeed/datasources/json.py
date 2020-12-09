from . import DataSource
import json

class JsonDataSource(DataSource):
    """Loads data from a continual list of multile json dictionary records"""
    def __init__(self, conf):
        super().__init__(conf)
        
        self._file_handle = self.config('file_handle', datatype='file_handle',
                                        help="A python3 opened file handle for the BRO json data to be streamed")
        self._file = self.config('file',
                                 help="The file name to read the bro json data stream from")
        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")
        self._time_column = self.config('time_column', default='ts',
                                        help="Time column to use when searching through data")

    def initialize(self):
        super().initialize()
        if not self._file_handle and not self._file:
            self.config_error("either file_handle or file is required for the %s module" % (type(self)))

    def open(self):
        if not self._file_handle:
            self._file_handle = open(self._file, "r")

        self.maybe_skip_to_time()

    def maybe_skip_to_time(self):
        if self._begin_time:
            # find the start of the data based on time
            while True:
                row = next(self)
                if self.parse_time(row[self._time_column]) >= self._begin_time:
                    break

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            row = next(self._file_handle)
            row = json.loads(row)
            if self._end_time and self.parse_time(row[self._time_column]) >= self._end_time:
                raise StopIteration()
            if not self.drop_or_prioritize(row):
                break # don't filter

        return row

