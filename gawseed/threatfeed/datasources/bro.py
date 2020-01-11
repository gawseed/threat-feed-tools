from pyfsdb.Fsdb import RETURN_AS_DICTIONARY,Fsdb

from gawseed.threatfeed.datasources.fsdb import FsdbDataSource

class BroDataSource(FsdbDataSource):
    def __init__(self, conf):
        super().__init__(conf)
        self._file_handle = self.config('file_handle')
        self._file = self.config('file')

    def open(self):
        if self._file and not self._file_handle:
            self._file_handle = open(self._file, "r")
        
        column_names = None
        for line in self._file_handle:
            if line[0] != "#": # skip at end of headers
                break

            if line[0:7] == "#fields":
                column_names = line.replace(".", "_").split("\t")
                column_names.pop(0)

        if not column_names:
            raise ValueError("passed bro file isn't in expected bro file format")

        self._fh = Fsdb(file_handle=self._file_handle,
                        return_type=RETURN_AS_DICTIONARY)
        self._fh.column_names = column_names
        # todo:: XXX: we eat a line here; fix this
