import sys
import json

from gawseed.threatfeed.config import Config

from kafka import KafkaConsumer
from kafka.structs import TopicPartition

class KafkaThreatFeed(Config):
    """Pulls threat data from a GAWSEED project (or other) kafka threat-feed source."""
    def __init__(self, conf):
        super().__init__(conf)
        self.require(['bootstrap_servers', 'topic', 'partition'])

        self._bootstrap_servers = self.config('bootstrap_servers',
                                              help="A list of kafka bootstrap servers to query")
        self._topic = self.config('topic',
                                  help="The kafka topic to stream from")
        self._partition = self.config('partition',
                                      help="The kafka partition to stream from")
        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._timeout = self.config('timeout',
                                                help="A timeout in milliseconds to wait for server data.")
        self._max_records = self.config('limit',
                                        help="Maximum number of records to retrieve")
        self._exclude_list = self.config('exclude', [],
                                         help='A list of entries to ignore in the threat feed')

    def open(self):
        self._consumer = KafkaConsumer(bootstrap_servers=self._bootstrap_servers,
                                       consumer_timeout_ms=self._timeout)

        # point to what we want at
        partition = TopicPartition(self._topic, self._partition)
        self._consumer.assign([partition])

        offset = None
        if self._begin_time:
            timestamp = self._begin_time * 1000
            offinfo = self._consumer.offsets_for_times({partition: timestamp})
            if offinfo == None or offinfo[partition] == None:
                raise ValueError("There is no data in the threat feed stream the begin date")
            offset = offinfo[partition].offset
            self._consumer.seek(partition, offset)

        if type(self._exclude_list) != list:
            self._exclude_list = [self._exclude_list]

    def __iter__(self):
        return self

    def parse_record(self, record):
        entry = json.loads(record.value)
        return entry

    def __next__(self):
        return next(self._consumer)

    def read(self, max_records=None, value_column='value'):
        array = []
        dictionary = {}
        if not max_records:
            max_records = self._max_records

        if self._begin_time:
            timestamp = self._begin_time

        for (count, entry) in enumerate(self._consumer):
            try:
                entry = self.parse_record(entry)

                # tmp hack to work around kafka hanging on some topics;
                # thus we start from the beginning and read everything.
                # this naturally won't scale.
                if timestamp and int(float(entry['timestamp'])) < timestamp:
                    continue

                if value_column not in entry:
                    continue

                if entry[value_column] in self._exclude_list:
                    continue
                
                array.append(entry)
                dictionary[entry[value_column]] = entry # note, may erase older ones; build array?
            except Exception as e:
                sys.stderr.write("dropping kafka feed entry due to a parse error: " + str(entry) + "\n")
                sys.stderr.write(str(e) + "\n")
                
            if max_records and count >= max_records:
                break

        return (array, dictionary)

