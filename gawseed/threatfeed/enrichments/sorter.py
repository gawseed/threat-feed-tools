from gawseed.threatfeed.config import Config

class EnrichmentSort(Config):
    """Sorts an existing enrichment dataset and puts it back"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_key'])

        self._enrichment_key = self.config("enrichment_key",
                                           help="The enrichment key for the data to be sorted")
        self._sort_key = self.config("sort_key", "ts",
                                     help="Sort the enrichment data by this key")

    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""
        # extract the current data
        if self._enrichment_key not in enrichment_data:
            return (None, None)

        data = enrichment_data[self._enrichment_key]
        data = sorted(data, key=lambda x: x[self._sort_key])
        enrichment_data[self._enrichment_key] = data

        return (self._output_key, data)
