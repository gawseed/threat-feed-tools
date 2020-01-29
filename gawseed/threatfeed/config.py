import re
import time
from dateutil import parser

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

    def config(self, name, default=None, help=None, datatype=None):
        if 'dump_config' in self._config:
            if help:
                print("      # %s: %s" % (name, help))
            print("      %s: %s" % (name, default))
            return

        if name in self._config:
            value = self._config[name]
            
            if datatype and datatype == 'time':
                return self.parse_time(value)
            if datatype and datatype == 'offset':
                return self.parse_offset(value)

            return value
            
        return default

    def config_error(self, msg):
        raise ValueError(msg)

    def parse_offset(self, timestr):
        multipliers = {'m': 60,
                       'h': 3600,
                       'd': 3600*24,
                       'w': 3600*24*7,
                       'y': 3600*24*365.25}

        multiplier = 1
        if timestr[-1] in multipliers:
            multiplier = multipliers[timestr[-1]]
            timestr = timestr[:-1]

        value = float(timestr) * multiplier
        return value
        

    def parse_time(self, timestr):
        if timestr[0] == '+' or timestr[0] == '-':
            # return an offset from now
            now = time.time()
            return now + self.parse_offset(timestr)
        elif re.match("^@?[0-9]+$", timestr): # assume epoch seconds
            if timestr[0] == '@':
                timestr = timestr[1:]
            return float(timestr)
        else:
            # hope for the best that this can parse it
            return parser.parse(timestr).timestamp()
