"""A druid datasource module for the gawseed threat-feed project"""
import time
from pydruid.db import connect

from . import DataSource

class DruidDataSource(DataSource):
    """Connects to a druid server to query for records."""

    def __init__(self, conf):
        super().__init__(conf)

        self.require(['host', 'table'])

        self._host = self.config('host')
        self._port = self.config('port', '8888')
        self._path = self.config('path', '/druid/v2/sql')
        self._scheme = self.config('scheme', 'http')
        self._begin_time = self.config('begin_time', datatype='time')
        self._end_time = self.config('end_time', datatype='time')
        self._limit = self.config('limit', 10000)
        self._table = self.config('table')
        self._where = self.config("where")
        self._sql = self.config('sql')

        self._conn = None
        self._curs = None

    def format_unix_epoch(self, etime):
        """Converts a unix epoch timestamp into a druid comparable date
        string."""
        (tm_year, tm_mon, tm_mday, tm_hour, tm_min,
         tm_sec, tm_wday, tm_yday, tm_isdst) = time.gmtime(etime)
        formatted_time = "%04d-%02d-%02d %02d:%02d:%02d"
        formatted_time = formatted_time % (tm_year, tm_mon, tm_mday,
                                           tm_hour, tm_min, tm_sec)
        return formatted_time

    def set_hints(self, keynames, hints):
        if not self._where:
            clauses = []
            for keyname in keynames:
                for key in hints:
                    clauses.append("%s = '%s'" % (keyname, key)) # XXX: quote escaping/filtering
            self._where = " and ".join(clauses)

    def open(self):
        """Establishes a connection to the druid server."""
        self._conn = connect(host=self._host, port=self._port,
                             path=self._path, scheme=self._scheme)
        self._curs = self._conn.cursor()

        if not self._sql:
            # build the sql from our parameters
            self._sql = "select * from %s where " % (self._table)

            if self._begin_time:
                self._sql += "__time >= time_parse('%s') and " % \
                    (self.format_unix_epoch(self._begin_time))

            if self._end_time:
                self._sql += "__time <= time_parse('%s') and " % \
                    (self.format_unix_epoch(self._end_time))

            for item in self._exclude_list:
                self._sql += "%s <> '%s' and " % \
                    (self._exclude_key, item)
                

            if self._where:
                self._sql += " (" + self._where + ") and "

            if self._sql[-4:] == "and ": # strip off the trailing and
                self._sql = self._sql[:-4]

            if self._limit:
                self._sql = self._sql + "limit %d " % (self._limit)

        self._curs.execute(self._sql)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._curs)._asdict()
