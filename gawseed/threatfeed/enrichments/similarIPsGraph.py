import os
import tempfile
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as dates
from gawseed.threatfeed.config import Config

class SimilarIPsGraph(Config):
    """Summarizes connection information in BRO or similar data"""
    def __init__(self, conf, search_index, dataset, is_binary, loader=None):
        super().__init__(conf)

        self.require(['enrichment_key', 'output_key'])

        self._enrichment_key = self.config("enrichment_key",
                                           help="The similar ips key for the data to be graphed")
        self._output_dir = self.config('output_dir', '/tmp',
                                       help="The name of the output directory to store the generated png in")
        self._output_key = self.config('output_key', 'similarips_image',
                                       help="The output key to store the generated png file name in")
        self._output_type = self.config('output_type', 'png',
                                        help="The output format of the generated file.")
        self._match_key = self.config('match_key', 'value',
                                      help="The match key column name to be used")
        self._data_key = self.config('data_key', 'key',
                                     help="The data key to use within the data row")
        self._time_key = self.config('time_key', 'ts',
                                     help="The time key to use within the data row")

        self._seen = {}

    def gather(self, count, row, match, enrichment_data):
        """Plot a time graph of when similar addresses were seen"""
        # extract the current data

        if self._enrichment_key not in enrichment_data:
            self.verbose("key '" + self._enrichment_key +
                         "' is not in the enrichment data")
            return (None, None)

        if enrichment_data[self._enrichment_key]['status'] == 'error':
            return (None, None)
            
        (fh, name) = tempfile.mkstemp(dir=self._output_dir,
                                      suffix="." + self._output_type)
        os.close(fh)

        extra_addresses_x = []
        extra_addresses_y = []

        match_x = []
        match_y = []

        for n, address in enumerate(enrichment_data[self._enrichment_key]['cluster']):
            for timestamp in  enrichment_data[self._enrichment_key]['cluster'][address]['times']:
                tint = int(timestamp)
                if tint <= 0:
                    continue
                if self._data_key and row[self._data_key] == address:
                    match_x.append(tint)
                    match_y.append(n)
                else:
                    extra_addresses_x.append(tint)
                    extra_addresses_y.append(n)

        # create a figure and NxM subplots
        fig, (ax0) = plt.subplots(nrows=1, ncols=1, sharex=True)

        # set various parameters on the first subplot
        ax0.xaxis.set_major_formatter(dates.DateFormatter("%Y/%m/%d\n%H:%M"))
        ax0.set_title('Activity graph')

        if (len(extra_addresses_x)) > 0:
            extra_addresses_x = dates.epoch2num(extra_addresses_x)
            ax0.scatter(extra_addresses_x, extra_addresses_y,
                        s=5, label="Other Addresses")

        if (self._time_key):
            row_stamp = int(self.parse_time(row[self._time_key]))
            row_stamp = dates.epoch2num(row_stamp)
            ax0.plot([row_stamp, row_stamp],
                     [0, len(enrichment_data[self._enrichment_key]['cluster'])],
                     label="Event Time", linewidth=1, ms=1,
                     color="green")

        if (len(match_x)) > 0:
            match_x = dates.epoch2num(match_x)
            ax0.scatter(match_x, match_y,
                        s=5, color="red",
                        label="Matched address")

        plt.ylabel("Enumerated Addresses")
        ax0.legend(loc='best')

        # deals with long labels:
        plt.tight_layout()

        fig.set_dpi(150)
        fig.set_size_inches(11,7.5)
        matplotlib.rcParams.update({'font.size': 10})

        # save it to a file
        plt.savefig(name,
                    bbox_inches="tight", pad_inches=0)

        return (self._output_key, name)
