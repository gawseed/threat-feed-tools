from dateutil import parser
import json

from kafka import KafkaConsumer
from kafka.structs import TopicPartition

class KafkaThreatFeed():
    """Pulls threat data from a GAWSEED project (or other) kafka threat-feed source."""
    def __init__(self, bootstrap_servers, begin_time=None, topic="gawseed_ipaddresses", partition=0):
        self._bootstrap_servers = bootstrap_servers
        self._topic = topic
        self._partition = partition
        self._begin_time = begin_time

    def open(self):
        self._consumer = KafkaConsumer(bootstrap_servers=self._bootstrap_servers,
                                       consumer_timeout_ms=1000)

        # point to what we want at
        partition = TopicPartition(self._topic, self._partition)
        self._consumer.assign([partition])

        offset = None
        if self._begin_time:
            timestamp = parser.parse(self._begin_time).timestamp() * 1000
            offinfo = self._consumer.offsets_for_times({partition: timestamp})
            if offinfo == None or offinfo[partition] == None:
                raise ValueError("There is no data in the threat feed stream the begin date")
            offset = offinfo[partition].offset
            self._consumer.seek(partition, offset)

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

        timestamp = parser.parse(self._begin_time).timestamp()

        for (count, entry) in enumerate(self._consumer):
            entry = self.parse_record(entry)

            # tmp hack to work around kafka hanging on some topics;
            # thus we start from the beginning and read everything.
            # this naturally won't scale.
            if int(entry['timestamp']) < timestamp:
                continue

            array.append(entry)
            dictionary[entry[value_column]] = entry # note, may erase older ones; build array?
            if max_records and count >= max_records:
                break

        return (array, dictionary)

