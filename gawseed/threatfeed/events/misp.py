import pymisp
import time
import dateparser

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

        self._report_tags = self.config('info_fields',
                                       {'priority': 'P',
                                        'name': 'Match',
                                        'value': 'match',
                                        'id_resp_p': 'port',
                                        'q': 'query',
                                        'mime_type': 'mime',
                                        'host': 'host',
                                        'server_name': 'server',
                                        'uri': 'uri',
                                        'status': 'status',
                                        'source': 'src',
                                        },
                                       help="A list of fields to construct the info line with")

        self._attribute_tags = self.config('attribute_fields',
                                           {'ip_resp_h':
                                            ['ip-dst', 'Network activity'],

                                            'ip_resp_p':
                                            ['dst-port', 'Network activity'],

                                            'ip_orig_h':
                                            ['ip-src', 'Network activity'],

                                            'ip_orig_p':
                                            ['src-port', 'Network activity'],

                                            'server_name':
                                            ['hostname', 'Network activity'],

                                            'query':
                                            ['domain', 'Network activity'],
                                            },
                                           help="A row to misp attributes to use")

    def initialize(self):
        self._misp = pymisp.PyMISP(self._url, self._key, False) ### false
        self.load_extra_info()

    def construct_info(self, containers):
        output_parts = []
        for tag in self._report_tags:
            for container in containers:
                if tag in container:
                    output_parts.append(f"{self._report_tags[tag]}: {container[tag]}")
        return ", ".join(output_parts)

    def add_attributes(self, me, containers):
        for tag in self._attribute_tags:
            for container in containers:
                if tag in container:
                    me.add_attribute(type=self._attribute_tags[tag][0],
                                     category=self._attribute_tags[tag][1],
                                     value=container[tag])

    def write_row(self, count, row, match, enrichments, output_stream):
        me = pymisp.MISPEvent()

        extra_info = self._extra_information_by_tag
        tag = match['tag']

        containers = [row, match]
        if tag in extra_info:
            containers.append(extra_info[tag])

        # create the "subject" (info) line
        me.info = self.construct_info(containers)

        # create attributes
        self.add_attributes(me, containers)

        # set basic attributes
        me.published = False
        me.distribution = "1"
        try:
            ts = float(row['ts'])
            me.set_date(ts)
        except Exception:
            try:
                t = dateparser.parse(row['ts'])
                me.set_date(t.timestamp())
            except Exception:
                sys.stderr.write(f"couldn't convert date: {row['ts']}\n")

        # manually constructed attributes
        if 'uri' in row and row['uri'] != '-' and 'host' in row:
            me.add_attribute(type='url', category='Network activity',
                             value=f'http://{row["host"]}:{row["id_resp_p"]}{row["uri"]}')


        # add in the row itself
        row_description = ""
        for item in row:
            row_description += f"{item}: {row[item]}\n"
        me.add_attribute(type='text', category="External analysis",
                         value=row_description,
                         comment="zeek row")

        # and the match
        match_description = ""
        for item in match:
            match_description += f"{item}: {match[item]}\n"
        me.add_attribute(type='text', category="External analysis",
                         value=match_description,
                         comment="threat source information")

        # If there is an external link to use, add it
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
