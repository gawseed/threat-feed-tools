from collections import Counter
import dnssplitter

from gawseed.threatfeed.config import Config

from .summarizer import Summarizer

class DNSSummarizer(Summarizer):
    """Summarizes/counts data from dns requests from another enrichment
    module, counting the results by full query (into 'queries') and by
    domains and regpoints (in 'domains' and 'regpoints') respectively.
    """
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf, search_index, dataset, is_binary, loader)

        self._splitter = dnssplitter.DNSSplitter()
        self._splitter.init_tree()
        
    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""
        if not self.check_enrichment_data(enrichment_data):
            return (None, None)

        query_counter = Counter()
        domain_counter = Counter()
        regpoint_counter = Counter()
        for row in enrichment_data[self._enrichment_key]:
            if self._data_key in row:
                query_counter[row[self._data_key]] += 1
                split_dns = self._splitter.search_tree(row[self._data_key])
                if split_dns:
                    (prefix, domain, regpoint) = split_dns
                    domain_counter[domain] += 1
                    regpoint_counter[regpoint] += 1

        return (self._output_key, {
            'queries': dict(query_counter),
            'domains': dict(domain_counter),
            'regpoints': dict(regpoint_counter),
        })
                
