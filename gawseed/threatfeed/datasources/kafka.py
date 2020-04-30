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
        self._over_time = self.config('over_time', default="0m", datatype='offset',
                                      help="The amount of time to search before and after desired date in case records aren't organized well by kafka timestamps")
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
        if self._end_time:
            self._kafka_end_time = self._end_time + self._over_time

    def open(self):
        consumer = KafkaConsumer(bootstrap_servers=self._bootstrap_servers)
                                 #consumer_timeout_ms=self._consumer_timeout_ms)
        # point to what we want at
        partition = TopicPartition(self._topic,0)
        consumer.assign([partition])

        if self._begin_time:
            offinfo = consumer.offsets_for_times({partition: self._begin_time * 1000 - self._over_time})
            if offinfo == None or offinfo[partition] == None:
                raise ValueError("There is no data in the enterprise stream the begin date")
            offset = offinfo[partition].offset
            consumer.seek(partition, offset)

        self._consumer = consumer
        self.verbose("opened kafka datasource: " + str(self.get_config()))
        return self

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._consumer)
        decoded_row = unpackb(row.value)
        if self._end_time:
            # self.verbose("searching forward from:")
            # self.verbose(decoded_row)
            count = 0
            while True:
                count += 1
                decoded_time = decoded_row[self._time_column]
                decoded_time = self.decode_item(decoded_time)
                decoded_time = self.parse_time(decoded_time)
                if decoded_time >= self._kafka_end_time:
                    self.verbose("kafka end time reached: " + str(count)+ " rows")
                    raise StopIteration()

                # see if it's within the time window
                # and that it's not in the filter list
                if decoded_time >= self._begin_time \
                   and decoded_time <= self._end_time \
                   and entry[self._exclude_column] in self._exclude_list:
                    # self.verbose("row found after" + str(count)+ " rows")
                    return decoded_row

                # else continue searching for a row that does match
                row = next(self._consumer)
                decoded_row = unpackb(row.value)
                
        return decoded_row

    def default_is_binary(self):
        return True


