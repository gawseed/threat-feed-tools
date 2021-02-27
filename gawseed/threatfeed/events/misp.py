import sys
import pymisp
import time

from gawseed.threatfeed.events import EventStream

class EventMisp(EventStream):
    """Prints simple summaries of events found."""
    def __init__(self, conf):
        super().__init__(conf)
        self.require(['url', 'key'])
        self._url = self.config('url',
                                 help="misp website to connect to")
        self._key = self.config('key',
                                 help="misp key to use")
        self._extra_fields = self.config('extra_fields', [],
                                         help="Extra fields to include in the output")
        self._timestamp = self.config('timestamp','ts',
                                      help="The column name of the timestamp data")

    def initialize(self):
        self._misp = pymisp.PyMISP(self._url, self._key, False) ### false

    def write_row(self, count, row, match, enrichments, output_stream):
        me = pymisp.MISPEvent()

        me.info = f'GAWSEED: match: {match["tag"]} priority {match["priority"]}'
        me.published = False
        me.distribution="1"

        me.add_attribute(type='ip-dst', value=row['id_resp_h'],
                         category='Network activity')
        # me.add_attribute(type='dst-port', value=row['id_resp_p'],
        #                  category='Network activity')
        me.add_attribute(type='ip-src', value=row['id_orig_h'],
                         category='Network activity')
        # me.add_attribute(type='src-port', value=row['id_orig_p'],
        #                  category='Network activity')

        ts = time.gmtime(float(row['ts']))
        #me.date = f'{ts.tm_year}-{ts.tm_mon}-{ts.tm_mday}'
        me.set_date(float(row['ts']))

        # insert optional attributes depending on type
        if 'server_name' in row:
            me.add_attribute(type='hostname', category='Network activity',
                             value=row["server_name"])

        if 'uri' in row and row['uri'] != '-' and 'host' in row:
            me.add_attribute(type='url', category='Network activity',
                             value=f'http://{row["host"]}:{row["id_resp_p"]}{row["uri"]}')

        if 'query' in row and row['uri'] != '-' and 'host' in row:
            me.add_attribute(type='domain', category='Network activity',
                             value=row['query'])

        # fake a priority
        if 'priority' in match:
            if match['priority'] >= 8:
                me.threat_level = 1
                me.threat_level_id = 1
            elif match['priority'] >= 5:
                me.threat_level = 2
                me.threat_level_id = 2
            else:
                me.threat_level = 3
                me.threat_level_id = 3

        self._misp.add_event(me)
