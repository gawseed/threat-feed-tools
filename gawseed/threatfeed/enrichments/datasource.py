import json
import time
import sys

from gawseed.threatfeed.config import Config
import gawseed.threatfeed.loader as loader

class Datasource(Config):
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

        self._match_time_column = self.config('datasource_time_column', 'timestamp',
                                          help="The time column to use when extracting a match timestamp to search forward and backward from")
        
        self._datasource_key = self.config('datasource_key', 'id_orig_h',
                                           help="The key to use when searching through the datasource.")

        self._time_backward = self.config('time_backward', '2m', datatype='offset',
                                          help="The amount of time to get data from going backward from the match point")
        self._time_forward = self.config('time_forward', '2m', datatype='offset',
                                         help="The amount of time to get data from going forward from the match point")

        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the returned data in.")

    def gather(self, count, row, match):

        ds_config = self._datasource

        timestamp = float(row[self._match_time_column])
        ds_config['begin_time'] = '@' + str(timestamp - self._time_backward)
        ds_config['end_time'] = '@' + str(timestamp + self._time_forward)

        conf = { loader.YAML_KEY: [{loader.DATASOURCE_KEY: ds_config}] }

        data_source = loader.create_instance(conf, loader.DATASOURCE_KEY)
        data_source.initialize()

        print("------------------------------***")
        try:
            data_source.open()
        except Exception as e:
            print("end of file? " + str(e))
            return (self._output_key, []) # end of file
        print("------------------------------***")

        # how we should do it eventually:
        # conf = { loader.YAML_KEY: [{loader.SEARCHER_KEY: { 'module': 'ip',
        #                                                    'search_keys': [self._datasource_key]}}] }
        # searcher = loader._create_instance()

        match_value = row[self._match_key]
        
        print("------------------------------***")
        enrich_rows = []
        print(match_value)
        print(self._datasource_key)
        try:
            for enrich_row in data_source:
                if enrich_row[self._datasource_key] == match_value:
                    enrich_rows.append(enrich_row)
        except Exception as e:
            print("done? " + str(e))

        return (self._output_key, enrich_rows)
                
