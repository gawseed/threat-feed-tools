import re
import time
import sys
from dateutil import parser

class Config():
    def __init__(self, config={}):
        self._config = config
        self._number_re=re.compile("^@?[0-9.]+$")
        self._verbose = False
        if 'verbose' in config:
            self._verbose = True

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

        if 'use' in self._config:
            return # assume they'll pull it from something named

        for requirement in requirements:
            if requirement not in self._config:
                self.config_error("'%s' is a requirement argument for %s" % (requirement, type(self)))

    def config(self, name, default=None, help=None, datatype=None):
        if 'dump_config' in self._config:
            if help:
                print("      # %s: %s" % (name, help))
            print("      %s: %s" % (name, default))
            return

        value = default
        if name in self._config:
            value = self._config[name]

        if value is None:
            return None

        if datatype and datatype == 'time':
            return self.parse_time(value)

        if datatype and datatype == 'offset':
            return self.parse_offset(value)

        if datatype and (datatype == 'list' or datatype == list):
            if type(value) != list:
                value = [value]

        if datatype == 'file_handle' and value = 'stdin':
            value = sys.stdin
        
        return value

    def get_config(self):
        return self._config

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
        elif self._number_re.match(timestr): # assume epoch seconds
            if timestr[0] == '@':
                timestr = timestr[1:]
            return float(timestr)
        else:
            # hope for the best that this can parse it
            return parser.parse(timestr).timestamp()

    def verbose(self, message):
        if self._verbose:
            sys.stderr.write(str(message) + "\n")
