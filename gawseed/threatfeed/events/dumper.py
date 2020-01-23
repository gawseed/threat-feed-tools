import sys

from gawseed.threatfeed.events import EventStream

class EventStreamDumper(EventStream):
    """A debugging event reporter: just outputs python strings of matches found"""
    def __init__(self, conf):
        super().__init__(conf)

    def write(self, count, row, match, enrichments):
        self.output("match #" + str(count) + ":\n")
        self.output(str(row) + "\n")
        self.output("--\n")
        self.output(str(match) + "\n")
        self.output("--\n")
        self.output(str(enrichments) + "\n")
        self.output("--------------")
        

