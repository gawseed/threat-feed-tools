import sys

from gawseed.threatfeed.events import EventStream

class EventStreamDumper(EventStream):
    def __init__(self, stream=sys.stdout):
        super().__init__(stream)

    def write(self, count, row, match):
        self.output("match #" + str(count) + ":\n")
        self.output(str(row) + "\n")
        self.output("--\n")
        self.output(str(match) + "\n")
        self.output("--------------")

