import unittest

class test_feed_fsdb(unittest.TestCase):
    def test_loading(self):
        import gawseed.threatfeed.feeds.fsdb
        self.assertTrue(True, "loaded gawseed.threatfeed.feeds.kafka")
        
        created = gawseed.threatfeed.feeds.fsdb.FsdbThreatFeed({})
        self.assertEqual(type(created),
                         gawseed.threatfeed.feeds.fsdb.FsdbThreatFeed,
                         "created a gawseed.threatfeed.feeds.fsdb.FsdbThreatFeed")
