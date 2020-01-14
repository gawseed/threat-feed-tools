class Config():
    def __init__(self, config={}):
        self._config = config

    def set_defaults(self, defaults={}):
        for default in defaults:
            if default not in self_.config:
                self._config = defaults[default]

    def require(self, requirements):
        if type(requirements) != list:
            requirements = [requirements]
        for requirement in requirements:
            if requirement not in self._config:
                self.config_error("'%s' is a requirement argument for %s" % (requirement, type(self)))

    def config(self, name, default=None):
        if name in self._config:
            return self._config[name]
        return default

    def config_error(self, msg):
        raise ValueError(msg)
