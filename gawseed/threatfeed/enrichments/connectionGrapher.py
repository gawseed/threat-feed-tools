from gawseed.threatfeed.config import Config
import graphviz

class ConnectionGrapher(Config):
    """Summarizes connection information in BRO or similar data"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_key', 'output_key'])

        self._enrichment_key = self.config("enrichment_key",
                                           help="The enrichment key for the data to be graphed")
        self._output_dir = self.config('output_dir', '/tmp',
                                       help="The name of the output directory to store the generated png in")
        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the generated png file name in")
        self._output_type = self.config('output_type', 'png',
                                        help="The output format of the generated file.")

    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""
        # extract the current data
        if self._enrichment_key not in enrichment_data:
            return

        dot = graphviz.Digraph()
        
        for orig in enrichment_data[self._enrichment_key]:
            dot.node(orig)
            for dest in enrichment_data[self._enrichment_key][orig]:
                dot.node(dest)
                for port in enrichment_data[self._enrichment_key][orig][dest]:
                    dot.edge(orig, dest, label=("%s:%d" % (port, enrichment_data[self._enrichment_key][orig][dest][port])))

        dot.render("foo.png", self._output_dir, format=self._output_type)
        return (self._output_key, str(dot))
