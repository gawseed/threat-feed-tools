import pyfsdb
from . import DataSource

class FsdbDataSource(DataSource):
    def __init__(self, file_handle=None, file=None):
        self._file_handle = file_handle
        self._file = file

    def open(self):
        self._fh = fsdb.Fsdb(file_handle=self._file_handle, filename=self._file,
                             return_type=fsdb.RETURN_AS_DICTIONARY)

    def __iter__(self):
        return self

    def __next__(self):
        return (next(self._fh))

