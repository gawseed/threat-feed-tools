import sys

from gawseed.threatfeed.config import Config

class EventStream(Config):
    def __init__(self, conf):
        super().__init__(conf)
        stream = self.config('stream')
        if type(stream) == str:
            self._stream_pattern = stream
        else:
            self._stream_pattern = None
            if stream == None:
                self._stream = sys.stdout
            else:
                self._stream = stream

    def new_output(self, count):
        if self._stream_pattern:
            filename = self._stream_pattern % (count)
            self._stream = open(filename, "w")

    def maybe_close_output(self):
        if self._stream_pattern:
            self._stream.close()

    def output(self, something):
        self._stream.write(something)

    def maybe_convert(self, row):
        new_row = {}
        for key in row:
            value = row[key]
            if type(key) == bytes:
                key = key.decode()
            if type(value) == bytes:
                new_row[key] = value.decode()
            else:
                new_row[key] = value
        return new_row

    def write(self, count, row, match, enrichments):
        row = self.maybe_convert(row)
        self.write_row(count, row, match, enrichments)

