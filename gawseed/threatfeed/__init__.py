from gawseed.threatfeed.config import Config

class ThreatFeed(Config):
    """Base class for threat feeds"""
    def __init__(self, conf):
        super().__init__(conf)

        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")
        self._time_column = self.config('time_column',
                                        help="Time column to use when searching through data")

        self._exclude_list = self.config('exclude', [],
                                         help='A list of entries to ignore in the threat feed')

    def initialize(self):
        if type(self._exclude_list) != list:
            self._exclude_list = [self._exclude_list]

    def __iter__(self):
        return self

    def __next__(self):
        row = self.next_row(self._consumer)
        if self._end_time and row[self._time_column] >= self._end_time:
            raise StopIteration()
        return row
