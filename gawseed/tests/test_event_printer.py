import unittest

class test_event_printer(unittest.TestCase):
    def test_load_printer(self):
        import gawseed.threatfeed.events.printer
        self.assertTrue(True, "imported gawseed.threatfeed.events.printer")

        created = gawseed.threatfeed.events.printer.EventStreamPrinter()
        self.assertEqual(type(created),
                         gawseed.threatfeed.events.printer.EventStreamPrinter,
                         "created a gawseed.threatfeed.events.printer.EventStreamPrinter")
        
