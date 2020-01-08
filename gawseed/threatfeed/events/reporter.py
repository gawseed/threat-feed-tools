import sys
import jinja2

from gawseed.threatfeed.events import EventStream

class EventStreamReporter(EventStream):
    def __init__(self, stream=sys.stdout, jinja_template=None, jinja_extra_information=None):
        super().__init__(stream)
        self._jinja_template = jinja_template.read()
        if jinja_extra_information:
            self._jinja_extra_information = yaml.load(jinja_extra_information)
        else:
            self._jinja_extra_information = None

        self._template = jinja2.Template(self._jinja_template)

    def write_row(self, count, row, match):
        output = self._template.render({ 'count': count,
                                         'row': row,
                                         'match': match,
                                         'extra': self._jinja_extra_information})
        self.output(output)

