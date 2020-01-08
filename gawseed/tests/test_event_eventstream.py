import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.events
        self.assertTrue(True, "imported gawseed.threatfeed.events")

        created = gawseed.threatfeed.events.EventStream([])
        self.assertEqual(type(created),
                         gawseed.threatfeed.events.EventStream,
                         "created a gawseed.threatfeed.event.EventStream")
        
