import unittest

class test_event_reporter(unittest.TestCase):
    def test_load_reporter(self):
        import gawseed.threatfeed.events.reporter
        self.assertTrue(True, "imported gawseed.threatfeed.events.reporter")

        with open("/dev/null", "r") as t:
            created = gawseed.threatfeed.events.reporter.EventStreamReporter(jinja_template=t)
        self.assertEqual(type(created),
                         gawseed.threatfeed.events.reporter.EventStreamReporter,
                         "created a gawseed.threatfeed.events.reporter.EventStreamReporter")
        
