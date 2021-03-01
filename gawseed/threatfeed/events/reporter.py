import sys
import jinja2
import yaml

from gawseed.threatfeed.events import EventStream
from gawseed.threatfeed.events.extrainfo import ExtraInfo


class EventStreamReporter(EventStream, ExtraInfo):
    """Formats output based on a jinja2 template.  The template is passed
       the following data fields:
          count: the match number for this run
          row: the row of the data source that was matched
          match: the content from the threat feed that trigger the event
          extra: Any supplemental json data passed in the 'extra_information' 
                 config option
          enrichments: A dictionary of any enrichments that were retrieved"""
    def __init__(self, conf):
        super().__init__(conf)
        ExtraInfo.__init__(self, conf)

        self.require(['template'])
        self._template = self.config('template',
                                     help="The file name to use as the jinja2 template.")

    def initialize(self):
        self.load_extra_info()

        self._jinja_template = open(self._template, "r").read()
        loader = jinja2.FileSystemLoader("./")
        template = jinja2.Environment(loader=loader)
        self._template = template.from_string(self._jinja_template)

    def write_row(self, count, row, match, enrichments, output_stream):
        args = {'count': count,
                'row': row,
                'match': match,
                'extra': self._extra_information,
                'extra_dict': self._extra_information_by_tag,
                'enrichments': enrichments}
        output = self._template.render(args)
        self.output(output + "\n", output_stream)

