import os
import re
import time
import sys
import urllib3
import hashlib
import tempfile
from dateutil import parser


class Config():
    def __init__(self, config={}):
        self._config = config
        self._number_re = re.compile("^@?[0-9.]+$")
        self._verbose = False
        self._pool = urllib3.PoolManager()
        self._cache = {}
        if 'verbose' in config:
            self._verbose = True
        self._cache_time = self.config('cache_time', 3600,
                                       help="If set, will cache the data for a particular key for this number of seconds")
        self._cache_urldir = self.config('url_cache_directory',
                                         help="Directory to store cache items for duplicate downloads")


    def initialize(self):
        """Overridable function for doing things beyond config copying in __init__"""
        pass

    def set_defaults(self, defaults={}):
        for default in defaults:
            if default not in self._config:
                self._config = defaults[default]

    def require(self, requirements):
        if type(requirements) != list:
            requirements = [requirements]
        if 'dump_config' in self._config:
            print("      # required: " + str(requirements))
            return

        if 'use' in self._config:
            return  # assume they'll pull it from something named

        for requirement in requirements:
            if requirement not in self._config:
                self.config_error("'%s' is a requirement argument for %s" %
                                  (requirement, type(self)))

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

        if datatype == 'file_handle' and value == 'stdin':
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
        elif self._number_re.match(timestr):  # assume epoch seconds
            if timestr[0] == '@':
                timestr = timestr[1:]
            return float(timestr)
        else:
            # hope for the best that this can parse it
            return parser.parse(timestr).timestamp()

    def verbose(self, message):
        if self._verbose:
            sys.stderr.write(str(message) + "\n")

    def cache(self, key, value):
        if not self._cache_time:
            return value
        self._cache[key] = {'data': value,
                            'timestamp': time.time()}

        disk_cache_location = self.cache_url_location(key)
        if disk_cache_location:
            fp = tempfile.NamedTemporaryFile(dir=self._cache_urldir, delete=False)
            filename = fp.name
            fp.write(value.encode('utf-8'))
            fp.close()
            os.rename(filename, disk_cache_location)
        return value

    def check_cache(self, key):
        if not self._cache_time:
            return None

        if key in self._cache and time.time() < self._cache[key]['timestamp'] + self._cache_time:
            return self._cache[key]['data']

        disk_cache_location = self.cache_url_location(key)
        if disk_cache_location and os.path.exists(disk_cache_location):
            with open(disk_cache_location) as f:
                return f.read()

    def geturl(self, url, reqtype='GET', params={}):
        prior_results = self.check_cache(url)
        if prior_results:
            return prior_results

        self.verbose("Fetching URL: " + url)
        r = self._pool.request(reqtype, url)
        if r.status != 200:
            print("  failed to fetch URL:" + str(r.status))
            return None

        # XXX: check against the expected type (self._type)
        return self.cache(url, r.data)

    #
    # disk caching support
    #
    def cache_url_string(self, value):
        return hashlib.sha256(value.encode('utf-8')).hexdigest()[0:20]

    def cache_url_location(self, value):
        if not self._cache_urldir:
            return None
        return os.path.join(self._cache_urldir, self.cache_url_string(value))
