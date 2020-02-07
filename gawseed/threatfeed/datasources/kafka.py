from kafka import KafkaConsumer
from kafka.structs import TopicPartition
from msgpack import unpackb

from . import DataSource

class KafkaDataSource(DataSource):
    """Loads data from a Kafka data stream"""
    def __init__(self, conf):
        super().__init__(conf)

        self.require(['bootstrap_servers', 'topic'])

        self._bootstrap_servers = self.config('bootstrap_servers',
                                              help="A list of kafka bootstrap servers to query")
        self._begin_time = self.config('begin_time', datatype='time',
                                       help="The time to start searching from; no value will mean end of stream")
        self._end_time = self.config('end_time', datatype='time',
                                     help="The time to stop a search when reading; no value will mean don't stop streaming")
        self._time_column = self.config('time_column',
                                        help="Time column to use when searching through data")
        self._topic = self.config('topic',
                                  help="The kafka topic to search")
        self._consumer_timeout_ms = self.config('timeout',
                                                help="A timeout in milliseconds to wait for server data.")
        self._max_records = self.config('max_records',
                                        help="The maximum number of records to return")

    def initialize(self):
        super().initialize()
        if self._time_column:
            self._time_column = self.encode_item(self._time_column)

    def open(self):
        consumer = KafkaConsumer(bootstrap_servers=self._bootstrap_servers)
                                 #consumer_timeout_ms=self._consumer_timeout_ms)
        # point to what we want at
        partition = TopicPartition(self._topic,0)
        consumer.assign([partition])

        if self._begin_time:
            offinfo = consumer.offsets_for_times({partition: self._begin_time * 1000})
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
        if self._end_time and self.parse_time(decoded_row[self._time_column]) >= self._end_time:
            raise StopIteration()
        return decoded_row

    def default_is_binary(self):
        return True


