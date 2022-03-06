import sys
import jinja2
import yaml
import collections
import pyfsdb
from io import StringIO

from gawseed.threatfeed.events import EventStream

class Summarizer(EventStream):
    """Counts field values in a row and/or match and reports them at the end"""

    def __init__(self, conf):
        super().__init__(conf)

        self._match_values = collections.defaultdict(collections.Counter)
        self._row_values = collections.defaultdict(collections.Counter)
        self._in_close = False

        self._row_fields = \
            self.config('row_fields', default=[],
                        help="An array of row columns to summarize")
        self._match_fields = \
            self.config('match_fields', default=[],
                        help="An array of match columns to summarize")

        self._format = \
            self.config('format', default="fsdb",
                        help="Output format to use: text, fsdb, or json")


    def new_output(self, count, **kwargs):
        "only run the parent new_output during close()"
        if self._in_close:
            return super().new_output(count, **kwargs)

    def write(self, count, row, match, enrichments, stream):
        "Count each value for each requested key in match/row"
        for key in self._match_fields:
            self._match_values[key][match[key]] += 1
        for key in self._row_fields:
            self._row_values[key][row[key]] += 1

    def close(self):
        "output the results"
        self._in_close = True

        output = self.new_output(0, output_type="match")
        if self._format == "fsdb":
            output = pyfsdb.Fsdb(out_file_handle=output)
            output.out_column_names = ['type', 'key', 'value', 'count']

        for key in self._match_fields:
            for value in self._match_values[key]:
                if self._format == "fsdb":
                    output.append(['match', key, value,
                                   self._match_values[key][value]])
                else:
                    output.write(f"match {key} {value} = {self._match_values[key][value]}\n")

        # XXX: fix this ugly hack
        if self._format == "fsdb" and not isinstance(self._stream, StringIO):
            output.close()
            self._stream = None
        else:
            self.maybe_close_output(output)

        output = self.new_output(1, output_type="row")
        if self._format == "fsdb":
            output = pyfsdb.Fsdb(out_file_handle=output)
            output.out_column_names = ['type', 'key', 'value', 'count']

        for key in self._row_fields:
            for value in self._row_values[key]:
                if self._format == "fsdb":
                    output.append(['row', key, value,
                                   self._row_values[key][value]])
                else:
                    output.write(f"row {key} {value} = {self._row_values[key][value]}\n")

      
        self.maybe_close_output()
        if self._format == "fsdb":
            output.close()
