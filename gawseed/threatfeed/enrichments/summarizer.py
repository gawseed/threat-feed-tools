from gawseed.threatfeed.config import Config

from collections import Counter

class Summarizer(Config):
    """Summarizes/counts data from another enricher's data;
    Produces a dictionary with data_key/count pairs"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_key', 'data_key'])

        self._data_key = self.config("data_key",
                                     help="The data key to summarize data by")
        self._enrichment_key = self.config("enrichment_key",
                                           help="The enrichment key for the data to be sorted")
        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the returned data in.")

    def check_enrichment_data(self, enrichment_data):
        if self._enrichment_key not in enrichment_data:
            self.verbose("summarizer data wasn't present")
            self.verbose("  keys present:" + str(enrichment_data.keys()))
            self.verbose(self.get_config())
            return False

        if type(enrichment_data[self._enrichment_key]) != list:
            self.verbose("summarizer data wasn't in a list: " + type(enrichment_data[self._enrichment_key]))
            self.verbose(self.get_config())
            return False

        return True

    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""

        if not self.check_enrichment_data(enrichment_data):
            return (None, None)

        counter = Counter()
        for row in enrichment_data[self._enrichment_key]:
            if self._data_key in row:
                counter[row[self._data_key]] += 1

        return (self._output_key, dict(counter))
