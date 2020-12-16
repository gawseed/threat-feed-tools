import json
import time
import sys
import traceback

from gawseed.threatfeed.config import Config

class Datasource(Config):
    """Pulls enrichment data from another datasource based on a key
    ("match_key") in the row that was matched by the searcher.  It
    matches this key against a key from the datasource:
    "datasource_key.  When a match is found, data will be gathered
    backward and forward from that time based on the specified
    backward_time and forward_time values.  The set of rows matched
    will be returned as an array.
    """
    def __init__(self, conf, search_index, data, is_binary, loader=None):
        super().__init__(conf)

        self.require(['datasource'])

        self._datasource = self.config('datasource',
                                       help="A dictionary describing a datasource to pull data from.")
        self._match_key = self.config('match_key', 'id_orig_h',
                                      help="The key to use when extracting search data from the matched row.")

        self._datasource_time_column = self.config('datasource_time_column', 'timestamp',
                                          help="The time column to use when extracting a match timestamp to search forward and backward from")
        
        self._datasource_key = self.config('datasource_key', 'id_orig_h',
                                           help="The key to use when searching through the datasource.")

        self._time_backward = self.config('time_backward', '2m', datatype='offset',
                                          help="The amount of time to get data from going backward from the match point")
        self._time_forward = self.config('time_forward', '2m', datatype='offset',
                                         help="The amount of time to get data from going forward from the match point")

        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the returned data in.")

        self._loader = loader

    def gather(self, count, row, match, enrichment_data = {}):

        ds_config = self._datasource

        timeval = row[self._datasource_time_column]
        timestamp = self.parse_time(timeval)
        ds_config['begin_time'] = '@' + str(timestamp - self._time_backward)
        ds_config['end_time'] = '@' + str(timestamp + self._time_forward)

        # have the loader create the data_source from the config
        data_source = self._loader.create_instance(ds_config,
                                                   self._loader.DATASOURCE_KEY)
        data_source.initialize()

        # Have the loader create a searcher to search the data source
        conf = { 'module': 'ip',
                 'search_keys': [self._datasource_key]}

        search_index = {row[self._match_key]: row}
        searcher = self._loader.create_instance(conf, self._loader.SEARCHER_KEY,
                                                [search_index, data_source,
                                                 data_source.is_binary()])

        # tell the datasource to start up
        try:
            data_source.open()
        except Exception as e:
            print("no data at start -- end of file? " + str(e))
            return (self._output_key, []) # end of file

        self.verbose("enrichment/datasource searcher created")
        self.verbose("  searching from " + str(ds_config['begin_time']) + " to " + str(ds_config['end_time']))
        self.verbose("  " + str(self.get_config()))

        # collect everything from the datasource into a row 
        enrich_rows = []
        try:
            for finding in searcher:
                enrich_rows.append(finding[0])
        except Exception as e:
            print(traceback.format_exc())
            print("done searching? exception: " + str(e))

        self.verbose("  found " + str(len(enrich_rows)) + " rows for key=" + self._output_key)

        # return the key, and the found rows
        return (self._output_key, enrich_rows)
                
