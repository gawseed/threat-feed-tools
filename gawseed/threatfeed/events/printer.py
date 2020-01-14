import sys

from gawseed.threatfeed.events import EventStream

class EventStreamPrinter(EventStream):
    def __init__(self, conf):
        super().__init__(conf)
        self._form = self.config('format', "  %-30.30s: %s\n")
        self._extra_fields = self.config('extra_fields', [])
        self._timestamp = self.config('timestamp','ts')

    def out(self, info1, info2):
        self.output(self._form % (str(info1) + ":", str(info2)))

    def out_if(self, info1, row, key):
        if key in row:
            self.out(info1, row[key])

    def write_row(self, count, row, match):
        self.output("match #" + str(count) + ":\n")

        self.output("Threat information:\n")
        self.out_if("Match value", match, 'value')
        self.out_if("Tag", match, 'tag')

        self.output("Data source information:\n")
        self.out_if("Timestamp", row, self._timestamp)
        self.out_if("id_orig_h", row, 'id_orig_h')
        self.out_if("id_resp_h", row, 'id_resp_h')

        if len(self._extra_fields) > 0:
            self.output("Extra information:\n")
            for field in self._extra_fields:
                self.out_if(field, row, field)

        self.output("-" * 70 + "\n")

