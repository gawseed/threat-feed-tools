import unittest

class test_feed_kafka(unittest.TestCase):
    def test_kafka_load(self):
        import gawseed.threatfeed.feeds.kafka
        self.assertTrue(True, "loaded gawseed.threatfeed.feeds.kafka")

        created = gawseed.threatfeed.feeds.kafka.KafkaThreatFeed(['bogus'])
        self.assertEqual(type(created),
                         gawseed.threatfeed.feeds.kafka.KafkaThreatFeed,
                         "created a gawseed.threatfeed.feeds.kafka.KafkaThreatFeed")


    # todo:: test routine for pulling data from a fake kafka server
