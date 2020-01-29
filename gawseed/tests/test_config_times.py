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
        
