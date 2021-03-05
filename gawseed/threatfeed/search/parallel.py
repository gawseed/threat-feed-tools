from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED

from gawseed.threatfeed.search import Search
from gawseed.threatfeed.loader import Loader

class Parallel(Search):
    """Applies multiple searches in parallel using multi-processes"""
    def __init__(self, conf, search_list, data_iterator, binary_search):
        super().__init__(conf, search_list, data_iterator, binary_search)
        self._processes = self.config("processes", default=4,
                                       help="Number of processes to spawn in parallel")
        self._preload = self.config("preload",
                                    help="Number of records to preload into the queue for the processors (the default will be four times the number of processes if left unset)")

        self._searcher_conf = self.config("searcher",
                                     help="A dictionary key describing the searcher to use")

        self._loader = Loader()
        self._search_list = search_list
        self._data_source = data_iterator
        self._binary_search = binary_search

    def initialize(self):
        super().initialize()

        if not self._preload:
            self._preload = 4 * self._processes

        # create queue
        self._futures = {}
        self._futures_num = 0
        self._answers = []

        # create the executor pool
        self._pool = ProcessPoolExecutor(max_workers=self._processes,
                                         initializer=search_init,
                                         initargs=(self._loader,
                                                   self._searcher_conf,
                                                   self._search_list,
                                                   self._data_source,
                                                   self._binary_search))

    def shutdown(self):
        self._pool.shutdown()

    def __iter__(self):
        running = True
        while running:
            # load up the futures queue with PRELOAD items from the data source
            while len(self._futures) < self._preload:
                # get the next row
                try:
                    row = next(self._data_iterator)
                except Exception as e:
                    # on stop iteration of the datasource,
                    # we should stop running
                    # XXX: really need to keep looping to catch ending events 
                    running = False

                if not row:
                    continue

                # our data is not full, so just load an item
                self._futures_num += 1
                self._futures[self._futures_num] = \
                    self._pool.submit(search_one, (self._futures_num, row))

            # queue is full, so wait for a searcher to be done
            if len(self._futures) != 0:
                wait(self._futures.values(), return_when=FIRST_COMPLETED)
            else:
                self.verbose("stuck???")

            # process anything returned, deleting handled instances
            delete_these = []
            for f in self._futures:
                if self._futures[f].done():
                    (num, row, answer) = self._futures[f].result()
                    if answer:
                        self._answers.append((row, answer))
                    delete_these.append(num)

            for d in delete_these:
                del self._futures[d]

            if len(self._answers) > 0:
                (row, match) = self._answers.pop(0)
                yield (row, match)

        self.shutdown()
    

# sub-process searching / state

searcher=None

def search_init(loader, conf, search_index, data_source, binary_search):
    global searcher
    import random
    data_source.close()
    searcher = \
        loader.create_instance(conf, loader.SEARCHER_KEY,
                               [search_index,
                                data_source,
                                binary_search])
    
def search_one(args):
    (num, row) = args
    match = searcher.search(row)
    return (num, row, match)

