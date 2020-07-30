from gawseed.threatfeed.config import Config

class PrioritySum(Config):
    """Combines priorities found in the base match, and all enrichment
    data.  Uses the 'priority_adj' field as a search criteria.
    """
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf, search_index, dataset, is_binary, loader)
        
        self._output_key = self.config('output_key', 'priority_summary',
                                       help="The output key to store the summarized priority in.")

        self._search_key = self.config('search_key', 'priority_adj',
                                       help="The search key to use when finding priority adjustment fields.")

    def gather(self, count, row, match, enrichment_data):
        """Sum the various priority fields together for a final value."""

        priority = 0 # starting value

        if 'priority' in match:
            priority = match['priority'] # unlikely
        elif 'priority' in row:
            priority = row['priority'] # also unlikely
            
        if not self.check_enrichment_data(enrichment_data):
            return (None, None)

        for key in enrichment_data:
            edata = enrichment_data[key]
            if isinstance(edata, dict):
                edata = [edata]
            elif not isinstance(edata, list):
                continue # unknown type to search
            
            for data in edata:
                if isinstance(data, dict):
                    if self._search_key in data:
                        priority += edata[self._search_key]
                
        return (self._output_key, {
            self._output_key: priority
        })
                
