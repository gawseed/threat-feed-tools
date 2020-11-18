import sys
import jinja2
import yaml

from gawseed.threatfeed.events import EventStream

class ArchiveReporter(EventStream):
    """Archives the count/row/match/enrichments to a python structure with
    the same key names"""
    def __init__(self, conf):
        super().__init__(conf)

        self._format = self.config('format', 'pickle',
                                   help="The output format to use (currently only pickle).")

    def initialize(self):
        self._dumps = None
        if self._format == 'pickle':
            import pickle
            self._dumps = pickle.dumps
            self._output_type = "wb"
        elif self._format == 'json':
            import json
            self._dumps = json.dumps
        else:
            raise ValueError("Unsupported archive format: " + self._format)

    def write_row(self, count, row, match, enrichments, output_stream=None):
        output = self._dumps({ 'count': count,
                               'row': row,
                               'match': match,
                               'enrichments': enrichments})
        self.output(output, output_stream)

