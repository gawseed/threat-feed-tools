import unittest

class test_base_search(unittest.TestCase):
    def test_load_base_search(self):
        import gawseed.threatfeed.search.ssh
        self.assertTrue(True, "imported gawseed.threatfeed.search.ssh")

        created = gawseed.threatfeed.search.ssh.SSHSearch(None, None)
        self.assertEqual(type(created),
                         gawseed.threatfeed.search.ssh.SSHSearch,
                         "created a gawseed.threatfeed.search.ssh.SSHSearch")
        
