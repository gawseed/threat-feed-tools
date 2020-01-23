class Config():
    def __init__(self, config={}):
        self._config = config

    def initialize(self):
        """Overridable function for doing things beyond config copying in __init__"""
        pass

    def set_defaults(self, defaults={}):
        for default in defaults:
            if default not in self_.config:
                self._config = defaults[default]

    def require(self, requirements):
        if type(requirements) != list:
            requirements = [requirements]
        if 'dump_config' in self._config:
            print("      # required: " + str(requirements))
            return
        for requirement in requirements:
            if requirement not in self._config:
                self.config_error("'%s' is a requirement argument for %s" % (requirement, type(self)))

    def config(self, name, default=None, help=None):
        if 'dump_config' in self._config:
            if help:
                print("      # %s: %s" % (name, help))
            print("      %s: %s" % (name, default))
            return
        if name in self._config:
            return self._config[name]
        return default

    def config_error(self, msg):
        raise ValueError(msg)
