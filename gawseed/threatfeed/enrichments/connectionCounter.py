from gawseed.threatfeed.config import Config

class ConnectionCounter(Config):
    """Summarizes connection information in BRO or similar data"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_key', 'output_key'])

        self._orig_key = self.config('origin_key', 'id_orig_h',
                                     help="The origin key")
        self._resp_key = self.config('destination_key', 'id_resp_h',
                                     help="The destination key")
        self._port_key = self.config('destination_port', 'id_resp_p',
                                     help="The destination port to group by")
        self._enrichment_key = self.config("enrichment_key",
                                           help="The enrichment key for the data to be analyzed")
        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the analysis data in")

    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""
        # extract the current data
        if self._enrichment_key not in enrichment_data:
            return (None, None)

        conns = {}
        ports = {}
        for row in enrichment_data[self._enrichment_key]:
            orig = row[self._orig_key]
            resp = row[self._resp_key]
            port = row[self._port_key]

            if orig not in conns:
                conns[orig] = {resp: {port: 1}}
                continue

            if resp not in conns[orig]:
                conns[orig][resp] = {port: 1}
                continue

            if port not in conns[orig]:
                conns[orig][resp][port] = 1
            else:
                conns[orig][resp][port] += 1

            if port not in ports:
                ports[port] = 1
            else:
                ports[port] += 1
                
        results = {'connections': conns,
                   'ports': ports}
        return (self._output_key, conns)
