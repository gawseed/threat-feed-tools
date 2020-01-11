import sys

from gawseed.threatfeed.events import EventStream

class EventStreamPrinter(EventStream):
    def __init__(self, conf):
        super().__init__(conf)
        self._form = self.config('format, '"  %-30.30s: %s\n")
        self._extra_fields = self.config('extra_fields', [])

    def out(self, info1, info2):
        self.output(self._form % (info1 + ":", info2))

    def write_row(self, count, row, match):
        self.output("match #" + str(count) + ":\n")

        self.output("Threat information:\n")
        self.out("Match value", match['value'])
        self.out("Tag", match['tag'])

        self.output("Data source information:\n")
        self.out("Timestamp", row['ts'])
        self.out("id_orig_h", row['id_orig_h'])
        self.out("id_resp_h", row['id_resp_h'])

        if len(self._extra_fields) > 0:
            self.output("Extra information:\n")
            for field in self._extra_fields:
                if field in row:
                    self.out(field, row[field])
                if field in match:
                    self.out(field, match[field])

        self.output("-" * 70 + "\n")

