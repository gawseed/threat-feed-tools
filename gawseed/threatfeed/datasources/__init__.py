from gawseed.threatfeed.config import Config

class DataSource(Config):
    def __init__(self, conf):
        super().__init__(conf)

    def is_binary(self):
        return False
