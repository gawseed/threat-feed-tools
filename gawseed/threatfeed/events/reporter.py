import sys
import jinja2
import yaml

from gawseed.threatfeed.events import EventStream

class EventStreamReporter(EventStream):
    def __init__(self, conf):
        super().__init__(conf)

        self.require(['template'])

        self._jinja_template = open(self.config('template', "r")).read()
        self._template = jinja2.Template(self._jinja_template)

        self._jinja_extra_information = self.config('extra_information')
        if self._jinja_extra_information:
            self._jinja_extra_information = yaml.loads(self._jinja_extra_information, Loader=yaml.FullLoader)

    def write_row(self, count, row, match):
        output = self._template.render({ 'count': count,
                                         'row': row,
                                         'match': match,
                                         'extra': self._jinja_extra_information})
        self.output(output + "\n")

