import tempfile
import graphviz
import re
from gawseed.threatfeed.config import Config

class ConnectionGrapher(Config):
    """Summarizes connection information in BRO or similar data"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_keys', 'output_key'])

        self._enrichment_keys = self.config("enrichment_keys",
                                            datatype=list,
                                            help="The enrichment keys for the data to be graphed")
        self._output_dir = self.config('output_dir', '/tmp',
                                       help="The name of the output directory to store the generated png in")
        self._output_key = self.config('output_key', 'datasource',
                                       help="The output key to store the generated png file name in")
        self._output_type = self.config('output_type', 'png',
                                        help="The output format of the generated file.")

        self._renderer = self.config('renderer', 'fdp',
                                     help='The graphviz renderer to use')
        self._limit = self.config('limit', 100,
                                  help="Don't plot more than LIMIT edges")
        self._minbytes = self.config('minbytes', 0,
                                     help="don't show connections with less than this number of rx or tx bytes")
        self._highlight = self.config('highlight', ['id_orig_h', 'id_resp_h'],
                                      help="Key names from the matched data to highlight")

        self._seen = {}

    def add_node(self, dot, row, label):
        if label in self._seen:
            return self._seen[label]
        
        if label in self._highlight_values:
            self._seen[label] = dot.node(label, color="blue",
                                         fillcolor="lightblue",
                                         style='filled',
                                         shape="box")
        else:
            self._seen[label] = dot.node(label)

    def gather(self, count, row, match, enrichment_data):
        """Re-sort all the enrichment data based on the specified column"""
        # extract the current data

        num = 0
        dot = graphviz.Digraph(engine=self._renderer)

        # pull out the highlight values to check
        self._highlight_values = []
        for h in self._highlight:
            self._highlight_values.append(row[h])


        for enrichment_key in self._enrichment_keys:
            if enrichment_key not in enrichment_data:
                self.verbose("key '" + enrichment_key +
                             "' is not in the enrichment data")
                continue

            data = enrichment_data[enrichment_key]['connections']
            # build the graph via graphviz
            try:
                for orig in data:
                    for dest in data[orig]:
                        dest_created = False
                        for port in data[orig][dest]:
                            if data[orig][dest][port]['rxbytes'] > self._minbytes or \
                               data[orig][dest][port]['txbytes'] > self._minbytes:


                                self.add_node(dot, row, orig)
                                self.add_node(dot, row, dest)

                                label = ("%s:%s\nrx=%s\ntx=%s" % \
                                         (port,
                                          str(data[orig][dest][port]['count']),
                                          str(data[orig][dest][port]['rxbytes']),
                                          str(data[orig][dest][port]['txbytes'])))
                                dot.edge(orig, dest,
                                         label=label)
                                num += 1
                                if num > self._limit:
                                    raise ValueError("too many edges")

            except Exception as e:
                print(e)
                # XXX: we'll continue; think about right thing here
                        
                    
        # create a temporary file to store results in
        (fh, name) = tempfile.mkstemp(dir=self._output_dir,
                                      suffix="." + self._output_type)
        fh.close()

        # graphviz force-adds a suffix, so we remove ours before passing 
        prefixname = re.sub("." + self._output_type + "$", "", name)
        dot.render(prefixname, self._output_dir,
                   format=self._output_type)


        return (self._output_key, name)
