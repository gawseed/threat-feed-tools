import sys
import jinja2
import yaml
import collections
import pyfsdb
from io import StringIO
from logging import warning
from gawseed.threatfeed.events import EventStream


class MultiSummarizer(EventStream):
    """Counts field values in a row and/or match and reports them with many sub-keys at the end"""

    def __init__(self, conf):
        super().__init__(conf)

        self.data = {}
        self._in_close = False
        self.have_warned = False

        self._row_fields = \
            self.config('row_fields', [],
                        help="An array of row columns to summarize")

        self._format = \
            self.config('format',
                        help="Output format to use: text, fsdb, or json")

    def new_output(self, count, **kwargs):
        "only run the parent new_output during close()"
        if self._in_close:
            return super().new_output(count, **kwargs)

    def add_keys(self, keys, values, value=1):
        num_keys = len(keys)

        pointer = self.data
        for keynum in range(num_keys - 2):
            if keys[keynum] not in values:
                if not self.have_warned:
                    self.have_warned = True
                    warning(f"one time warning: failed to find {keys[keynum]} in {values}")
                return
            this_value = values[keys[keynum]]
            if this_value not in pointer:
                pointer[this_value] = {}
            pointer = pointer[this_value]

        if keys[-2] not in values:
            if not self.have_warned:
                self.have_warned = True
                warning(f"one time warning: failed to find {keys[-2]} in {values}")
            return
        this_value = values[keys[-2]]
        if this_value not in pointer:
            pointer[this_value] = collections.Counter()

        if keys[-1] not in values:
            if not self.have_warned:
                self.have_warned = True
                warning(f"one time warning: failed to find {keys[-1]} in {values}")
            return
        final_value = values[keys[-1]]
        pointer[this_value][final_value] += value

    def flatten_step(self, point, values, data):
        if isinstance(point, collections.Counter):
            # final step in the depth
            for key in point:
                data.append(values + [key, point[key]])
        else:
            for key in point:
                self.flatten_step(point[key], values + [key], data)

    def flatten(self):
        return_data = []
        self.flatten_step(self.data, [], return_data)
        return return_data

    def write(self, count, row, match, enrichments, stream):
        "Count each value for each requested key in match/row"
        self.add_keys(self._row_fields, row)

    def close(self):
        "output the results"
        self._in_close = True

        output = self.new_output(0, output_type="match")
        if self._format == "fsdb":
            output = pyfsdb.Fsdb(out_file_handle=output)
            output.out_column_names = self._row_fields + ['count']
        for row in self.flatten():
            output.append(row)

        if not (isinstance(output, StringIO) or
                output == sys.stdout or
                output == sys.stderr):
            output.close()
