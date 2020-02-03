import json
import time
import sys

from gawseed.threatfeed.config import Config

class EnrichmentURL(Config):
    """Pulls enrichment data from another datasource based on a key
    ("match_key") in the row that was matched by the searcher.  It
    matches this key against a key from the datasource:
    "datasource_key.  When a match is found, data will be gathered
    backward and forward from that time based on the specified
    backward_time and forward_time values.  The set of rows matched
    will be returned as an array.
    """
    def __init__(self, conf, search_index, data, is_binary):
        super().__init__(conf)

        self.require(['datasource'])

        self._datasource = self.config('datasource',
                                       help="A dictionary describing a datasource to pull data from.")
        self._match_key = self.config('match_key', 'id_orig_h',
                                      help="The key to use when extracting search data from the matched row.")

        self._datasource_key = self.config('datasource_key', 'id_orig_h',
                                           help="The key to use when searching through the datasource.")

        self._datasource_timekey = self.config('datasource_timekey', 'timestamp',
                                               help="The time column to use when searching forward and backward")

        self._time_backward = self.config('time_backward', '2m', datatype='offset',
                                          help="The amount of time to get data from going backward from the match point")
        self._time_forard = self.config('time_forward', '2m', datatype='offset',
                                          help="The amount of time to get data from going forward from the match point")

    def gather(self, count, row, match):
        timestamp = float(row[self._datasource_timekey])

        ds_config = self._config
        ds_config['begin_time'] = '@' + str(timestamp - self._time_backward)
        ds_config['end_time'] = '@' + str(timestamp - self._time_forward)

        ds = 
