from gawseed.threatfeed.config import Config

class ThreatFeed(Config):
    """Base class for threat feeds"""
    def __init__(self, conf):
        super().__init__(conf)

        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")
        self._time_column = self.config('time_column', default='timestamp',
                                        help="Time column to use when searching through data")

        self._value_column = self.config('key', 'value',
                                         help="The primary column/key name to use for pulling threat data")

        self._tag_column = self.config('tag', 'tag',
                                       help="The tag column name to use for matching priorities (see below)")

        self._exclude_list = self.config('exclude', [],
                                         help='A list of entries to ignore in the threat feed')
        self._priorities = self.config('priorities', {},
                                       help="A dictionary containing base priorities for each feed tag.  If unfound, a default of 0 will be used.")


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

    def drop_or_prioritize(self, entry, value_column, tag_column):
        if self._begin_time and int(float(entry[self._time_column])) < self._begin_time:
            return True
        
        if value_column not in entry:
            return True

        if entry[value_column] in self._exclude_list:
            return True

        if tag_column and \
           not entry.get('priority') and \
           self._priorities.get(entry.get(tag_column)):
            entry['priority'] = self._priorities[entry.get(tag_column)]

        return False
        
