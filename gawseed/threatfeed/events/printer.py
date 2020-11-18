import sys

from gawseed.threatfeed.events import EventStream

class EventStreamPrinter(EventStream):
    """Prints simple summaries of events found."""
    def __init__(self, conf):
        super().__init__(conf)
        self._form = self.config('format', "  %-30.30s: %s\n",
                                 help="The line format to use when printing")
        self._extra_fields = self.config('extra_fields', [],
                                         help="Extra fields to include in the output")
        self._timestamp = self.config('timestamp','ts',
                                      help="The column name of the timestamp data")

    def out(self, info1, info2, output_stream):
        self.output(self._form % (str(info1) + ":", str(info2)), output_stream)

    def out_if(self, info1, row, key, output_stream):
        if key in row:
            self.out(info1, row[key], output_stream)

    def write_row(self, count, row, match, enrichments, output_stream):
        self.output("match #" + str(count) + ":\n", output_stream)

        self.output("Threat information:\n", output_stream)
        self.out_if("Match value", match, 'value', output_stream)
        self.out_if("Tag", match, 'tag', output_stream)

        self.output("Data source information:\n", output_stream)
        self.out_if("Timestamp", row, self._timestamp, output_stream)
        self.out_if("id_orig_h", row, 'id_orig_h', output_stream)
        self.out_if("id_resp_h", row, 'id_resp_h', output_stream)

        if len(self._extra_fields) > 0:
            self.output("Extra information:\n", output_stream)
            for field in self._extra_fields:
                self.out_if(field, row, field, output_stream)

        self.output("-" * 70 + "\n", output_stream)

