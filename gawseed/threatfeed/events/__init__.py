import sys

from gawseed.threatfeed.config import Config

class EventStream(Config):
    def __init__(self, conf):
        super().__init__(conf)
        stream = self.config('stream')
        if type(stream) == str:
            if stream == "stdout":
                self._stream = sys.stdout
            elif stream == "stderr":
                self._stream = sys.stderr
            else:
                self._stream_pattern = stream
        else:
            self._stream_pattern = None
            if stream == None:
                self._stream = sys.stdout
            else:
                self._stream = stream # assume an opened filehandle

        self._output_type = "w"

    def new_output(self, count, **kwargs):
        if self._stream_pattern:
            if self._stream_pattern.find("%d") != -1:
                filename = self._stream_pattern % (count)
            else:
                filename = self._stream_pattern.format(count=count, **kwargs)

            self._stream = open(filename, self._output_type)

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
        self.verbose("created output for event %d" % (count,))
