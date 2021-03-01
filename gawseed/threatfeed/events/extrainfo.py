import yaml

from gawseed.threatfeed.config import Config


class ExtraInfo(Config):
    def __init__(self, conf):
        super().__init__(conf)

        self._jinja_extra_information = self.config('extra_information', {},
                                                    help="A YAML file name to be loaded as an extra_information field passed to the jinja2 template")
        self._jinja_extra_information_root = self.config('extra_information_root', 'feeds',
                                                    help="Optional root for the extra information to convert to a dictonary")
        self._jinja_extra_information_tag = self.config('extra_information_key', 'tag',
                                                    help="Optional tag for the extra information to convert to a dictonary")


        self._jinja_extra_information_by_tag = {}

    def load_extra_info(self):
        if self._jinja_extra_information:
            fh = open(self._jinja_extra_information, "r")
            self._jinja_extra_information = yaml.load(fh,
                                                      Loader=yaml.FullLoader)

        # refactor it into a tag dictionary version
        self._jinja_extra_information_by_tag = {}

        if self._jinja_extra_information:
            root_name = self._jinja_extra_information_root
            tag_name = self._jinja_extra_information_tag
            root = self._jinja_extra_information[root_name]
            for item in root:
                if tag_name in item:
                    self._jinja_extra_information_by_tag[item[tag_name]] = item
