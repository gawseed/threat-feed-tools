from dateutil import parser

from kafka import KafkaConsumer
from kafka.structs import TopicPartition
from msgpack import unpackb

from . import DataSource

class KafkaDataSource(DataSource):
    def __init__(self, bootstrap_servers,
                 begin_time=None, topic="ssh", max_records=None,
                 consumer_timeout_ms=None):
        super().__init__()
        self._bootstrap_servers = bootstrap_servers
        self._begin_time = begin_time
        self._topic = topic
        self._max_records = max_records
        self._consumer_timeout_ms = consumer_timeout_ms

    def open(self):
        consumer = KafkaConsumer(bootstrap_servers=self._bootstrap_servers)
                                 #consumer_timeout_ms=self._consumer_timeout_ms)
        # point to what we want at
        partition = TopicPartition(self._topic,0)
        consumer.assign([partition])

        if self._begin_time:
            timestamp = parser.parse(self._begin_time).timestamp() * 1000
            offinfo = consumer.offsets_for_times({partition: timestamp})
            if offinfo == None or offinfo[partition] == None:
                raise ValueError("There is no data in the enterprise stream the begin date")
            offset = offinfo[partition].offset
            consumer.seek(partition, offset)

        self._consumer = consumer
        return self

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._consumer)
        decoded_row = unpackb(row.value)
        return decoded_row

    def is_binary(self):
        return True


