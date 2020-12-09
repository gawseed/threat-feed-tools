import unittest
import io

from gawseed.threatfeed.loader import Loader
from gawseed.threatfeed.feeds.fsdb import FsdbThreatFeed

class test_feed_fsdb(unittest.TestCase):
    def test_loading(self):
        conf = {
            'threatsource': {
                'module': 'fsdb',
                'file': 'gawseed/tests/priority_threats.fsdb',
                'key': 'value',
                'tag': 'tag',
                'priorities': {
                    'tag2': '7',
                    'tag3': '5',  # overridden by feed
                }
        }}

        # create the source
        loader = Loader()
        threat_source = \
            loader.create_instance_for_module(conf, loader.THREATSOURCE_KEY)

        # tell it to "go"
        threat_source.open()
        (search_data, search_index) = threat_source.read()

        # check the contents
        self.assertEqual(len(search_data), 3)

        # check that all the values are right
        self.assertEqual(search_data[0]['priority'], '8')
        self.assertEqual(search_data[1]['priority'], '7')
        self.assertEqual(search_data[2]['priority'], '2')


if __name__ == '__main__':
    unittest.main()
