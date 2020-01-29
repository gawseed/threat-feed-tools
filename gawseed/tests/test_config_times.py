import unittest

class test_config_times(unittest.TestCase):
    def test_config_load(self):
        import gawseed.threatfeed.config
        self.assertTrue(True, "loaded config module")

    def test_config_convert_times(self):
        from gawseed.threatfeed.config import Config
        c = Config({})

        self.assertEqual(c.parse_offset("1d"), 86400.0, "1d parsed correctly")
        self.assertEqual(c.parse_offset("-2d"), -2*86400.0, "-2d parsed correctly")
        self.assertEqual(c.parse_offset("-3w"), -3*7*86400.0, "-3w parsed correctly")
        self.assertEqual(c.parse_offset("1y"), 31557600.0, "1y parsed correctly")
        self.assertEqual(c.parse_offset("5m"), 300.0, "5m parsed correctly")
        

    def test_config_dates(self):
        from gawseed.threatfeed.config import Config
        c = Config({})

        self.assertEqual(c.parse_time("1989-09-01 00:00:00Z"), 620611200.0,
                         "Parsed a date from 1989 correctly")
        # self.assertEqual(c.parse_time("1989/9/1"), 620611200.0, # assumes local timezone
        #                  "Parsed a date from 1989 correctly")
        self.assertEqual(c.parse_time("1989/9/1 01:23:45Z"), 620611200.0 + 3600 + 23*60 + 45,
                         "Parsed a date from 1989 correctly")
        self.assertEqual(c.parse_time("1989/9/1 01:23:45-02:00"),
                         620611200.0 + 3600 + 23*60 + 45 + 2*3600,
                         "Parsed a date from 1989 correctly")
        self.assertEqual(c.parse_time("12345"), 12345,
                         "Parsed a epoch correctly")
        self.assertEqual(c.parse_time("@12345"), 12345,
                         "Parsed an @epoch correctly")
        
