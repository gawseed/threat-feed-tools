import sys
import jinja2
import yaml

from gawseed.threatfeed.events import EventStream

class EventStreamReporter(EventStream):
    def __init__(self, conf):
        super().__init__(conf)

        self.require(['template'])
        self._template = self.config('template',
                                     help="The file name to use as the jinja2 template.")
        self._jinja_extra_information = self.config('extra_information', {},
                                                    help="A YAML file name to be loaded as an extra_information field passed to the jinja2 template")

    def initialize(self):
        self._jinja_template = open(self._template, "r").read()
        self._template = jinja2.Template(self._jinja_template)


        if self._jinja_extra_information:
            fh = open(self._jinja_extra_information, "r")
            self._jinja_extra_information = yaml.load(fh, Loader=yaml.FullLoader)

    def write_row(self, count, row, match, enrichments):
        output = self._template.render({ 'count': count,
                                         'row': row,
                                         'match': match,
                                         'extra': self._jinja_extra_information,
                                         'enrichments': enrichments})
        self.output(output + "\n")

