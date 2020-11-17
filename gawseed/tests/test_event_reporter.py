import unittest


class test_event_reporter(unittest.TestCase):
    def test_load_reporter(self):
        import gawseed.threatfeed.events.reporter
        self.assertTrue(True, "imported gawseed.threatfeed.events.reporter")

        created = gawseed.threatfeed.events.reporter.EventStreamReporter({'template': "/dev/null"})
        self.assertEqual(type(created),
                         gawseed.threatfeed.events.reporter.EventStreamReporter,
                         "created a reporter.EventStreamReporter")

