import pyfsdb
from . import DataSource

class FsdbDataSource(DataSource):
    def __init__(self, conf):
        super().__init__(conf)
        
        self._file_handle = self.config('file_handle')
        self._file = self.config('file')

        if not self._file_handle and not self._file:
            self.config_error("either file_handle or file is required for the %s module" % (type(self)))

    def open(self):
        self._fh = pyfsdb.Fsdb(file_handle=self._file_handle, filename=self._file,
                               return_type=pyfsdb.RETURN_AS_DICTIONARY)

    def __iter__(self):
        return self

    def __next__(self):
        return (next(self._fh))

