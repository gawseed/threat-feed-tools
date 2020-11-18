import sys
import os.path
import pathlib
from io import StringIO

from gawseed.threatfeed.config import Config

class EventStream(Config):
    def __init__(self, conf):
        super().__init__(conf)
        stream = self.config('stream',
                             help="The stream name or filename to write to. This may be 'stdout' or 'stderr' to write to those unix streams, or may be a filename.  If a filename, then you can include tokens from the row or match data in the filename using {} wrappers around the name with 'count', row', and 'match' variables describing the data.  For example: path/{row[id_orig_h]}.txt will pull out a origin IP from bro datasets.  OR (but not both) you can include a '%d' which will be replaced by the event number.")

        if type(stream) == str:
            if stream == "stdout":
                self._stream = StringIO()
            elif stream == "stderr":
                self._stream = sys.stderr
            else:
                self._stream_pattern = stream
        else:
            self._stream_pattern = None
            if stream == None:
                self._stream = StringIO()
            else:
                self._stream = stream # assume an opened filehandle

        self._output_type = "w"

    def open_file(self, filename):
        dir = os.path.dirname(filename)
        if not os.path.isdir(dir):
            pathlib.Path(dir).mkdir(parents=True, exist_ok=True)
        return open(filename, self._output_type)

    def new_output(self, count, **kwargs):
        output_stream = None
        if self._stream_pattern:
            if self._stream_pattern.find("%d") != -1:
                filename = self._stream_pattern % (count)
            else:
                filename = self._stream_pattern.format(count=count, **kwargs)

            # mkdir and open
            output_stream = self.open_file(filename)
            self._stream = output_stream

        return output_stream

    def maybe_close_output(self, output_stream=None):
        if not output_stream:
            output_stream = self._stream
        if isinstance(output_stream, StringIO):
            sys.stdout.write(output_stream.getvalue())
        if self._stream_pattern:
            output_stream.close()

    def output(self, something, output_stream=None):
        if not output_stream:
            output_stream = self._stream
        output_stream.write(something)

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

    def write(self, count, row, match, enrichments, output_stream=None):
        if not output_stream:
            output_stream = self._stream
        row = self.maybe_convert(row)
        self.write_row(count, row, match, enrichments, output_stream)
        self.verbose("created output for event %d" % (count,))
