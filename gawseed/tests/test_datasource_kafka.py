import unittest

class test_datasource_kafka(unittest.TestCase):
    def test_load_datasource_kafka(self):
        import gawseed.threatfeed.datasources.kafka
        self.assertTrue(True, "imported gawseed.threatfeed.datasources.kafka")

        created = gawseed.threatfeed.datasources.kafka.KafkaDataSource({'bootstrap_servers': ['bogus'],
                                                                        'topic': 'bogus'})
        self.assertEqual(type(created),
                         gawseed.threatfeed.datasources.kafka.KafkaDataSource,
                         "created a gawseed.threatfeed.datasources.kafka.KafkaDataSource")
        

