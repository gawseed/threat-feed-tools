import sys

from gawseed.threatfeed.events import EventStream

class EventStreamDumper(EventStream):
    """A debugging event reporter: just outputs python strings of matches found"""
    def __init__(self, conf):
        super().__init__(conf)

        self._pretty_print = self.config("pretty", default=False,
                                         help="Pretty print the results")

    def initialize(self):
        if self._pretty_print:
            import pprint
            self._printer = pprint.pformat
        else:
            self._printer = str

    def write(self, count, row, match, enrichments):
        self.output("match #" + self._printer(count) + ":\n")
        self.output("row: " + self._printer(row) + "\n")
        self.output("--\n")
        self.output("match: " + self._printer(match) + "\n")
        self.output("--\n")
        self.output("enrichments: " + self._printer(enrichments) + "\n")
        self.output("--------------")
