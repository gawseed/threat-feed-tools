import pymisp
import time

from gawseed.threatfeed.events import EventStream
from gawseed.threatfeed.events.extrainfo import ExtraInfo


class EventMisp(EventStream, ExtraInfo):
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

        self._web_report_urls = self.config('web_report_urls', [],
                                      help="A location to link to a html or other produced report")

    def initialize(self):
        self._misp = pymisp.PyMISP(self._url, self._key, False) ### false
        self.load_extra_info()

    def write_row(self, count, row, match, enrichments, output_stream):
        me = pymisp.MISPEvent()

        extra_info = self._extra_information_by_tag
        tag = match['tag']

        me.info = f'P{match["priority"]} Match: {extra_info[tag]["name"]}, match: {extra_info[tag]["data_type"]}={match["value"]}, port={row["id_resp_p"]}'
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

        me.set_date(float(row['ts']))

        # insert optional attributes depending on type
        if 'server_name' in row:
            me.add_attribute(type='hostname', category='Network activity',
                             value=row["server_name"])

        if 'uri' in row and row['uri'] != '-' and 'host' in row:
            me.add_attribute(type='url', category='Network activity',
                             value=f'http://{row["host"]}:{row["id_resp_p"]}{row["uri"]}')

        if 'query' in row and row['query'] != '-':
            me.add_attribute(type='domain', category='Network activity',
                             value=row['query'])

        row_description = ""
        for item in row:
            row_description += f"{item}: {row[item]}\n"
        me.add_attribute(type='text', category="External analysis",
                         value=row_description,
                         comment="zeek row")

        match_description = ""
        for item in match:
            match_description += f"{item}: {match[item]}\n"
        me.add_attribute(type='text', category="External analysis",
                         value=match_description,
                         comment="threat source information")

        if self._web_report_urls:
            if not isinstance(self._web_report_urls, list):
                self._web_report_urls = [self._web_report_urls]

            for url in self._web_report_urls:
                location = url.format(count=count,
                                      row=row,
                                      match=match,
                                      enrichments=enrichments)
                me.add_attribute(type='link', category="External analysis",
                                 value=location,
                                 comment="GAWSEED report")

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
