import unittest

class test_event_dumper(unittest.TestCase):
    def test_load_base_dumper(self):
        import gawseed.threatfeed.events.dumper
        self.assertTrue(True, "imported gawseed.threatfeed.events.dumper")

        created = gawseed.threatfeed.events.dumper.EventStreamDumper({})
        self.assertEqual(type(created),
                         gawseed.threatfeed.events.dumper.EventStreamDumper,
                         "created a gawseed.threatfeed.event.EventStream")
        
