import sys
import jinja2
import yaml
import collections

from gawseed.threatfeed.events import EventStream

class Summarizer(EventStream):
    """Counts field values in a row and/or match and reports them at the end"""

    def __init__(self, conf):
        super().__init__(conf)

        self._row_fields = \
            self.config('row_fields',
                        help="An array of row columns to summarize")
        self._match_fields = \
            self.config('match_fields',
                        help="An array of match columns to summarize")
        self._match_values = collections.defaultdict(collections.Counter)
        self._row_values = collections.defaultdict(collections.Counter)

    def write(self, count, row, match, enrichments, stream):
        "Count each value for each requested key in match/row"
        for key in self._match_fields:
            self._match_values[key][match[key]] += 1
        for key in self._row_fields:
            self._row_values[key][row[key]] += 1

    def close(self):
        "output the results"
        output = self.new_output(0, output_type="match")
        for key in self._match_fields:
            for value in self._match_values[key]:
                output.write(f"match {key} {value} = {self._match_values[key][value]}\n")
        self.maybe_close_output(output)

        output = self.new_output(1, output_type="row")
        for key in self._row_fields:
            for value in self._row_values[key]:
                output.write(f"row {key} {value} = {self._row_values[key][value]}\n")
        self.maybe_close_output(output)
