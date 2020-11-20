#!/usr/bin/python3

"""This is a generic threat-feed searching application that takes a
threat feed of various types and matches it against sources of network
log data to search through.  It can take both threat-feeds and log
data from multiple sources, including kafka and files.  It's output is
configurable and can be given a jinja2 template for generic report
generation.
"""

import sys
import argparse
from copy import deepcopy

import traceback

import multiprocessing
import threading
import queue

from gawseed.threatfeed.loader import Loader

debug = False

loader = None


def parse_args():
    formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(formatter_class=formatter,
                                     description="""This uses data from threat
                                     feeds (in kafka topics or files) to search
                                     through network data (from kafka or
                                     files) and reports any matches
                                     as 'events'.""")

    # THREAT FEEDS
    # ----------------------------------------------------------------------
    # arguments for the threat feed source
    group = parser.add_argument_group("Threat feed arguments")
    group.add_argument("-B", "--threat-begin-time", default=None, type=str,
                       help="Date to start returning threat feed data from")

    group.add_argument("-E", "--threat-end-time", default=None, type=str,
                       help="Date to stop returning threat feed data after")

    group.add_argument("-M", "--threat-max-records", default=None, type=int,
                       help="Maximum number of threat records to retrieve" +
                       " and search for ")

    group.add_argument("--threat-timeout", default=1000, type=int,
                       help="Maximum number of ms to wait for a threat " +
                       " feed before figuring its done")

    # arguments for kafka threat feeds
    group = parser.add_argument_group("Kafka specific threat feed arguments")
    group.add_argument("-K", "--threat-kafka-servers", default=[], type=str,
                       nargs="*", help="Kafka server to pull topics from")

    group.add_argument("--threat-kafka-topic", default="gawseed_ipaddresses",
                       type=str, help="The kafka threat topic to" +
                       " use as the threat source")

    group = parser.add_argument_group("File/FSDB specific threat  " +
                                      "feed arguments")
    # arguments for file based threat feeds
    group.add_argument("--threat-fsdb", default=None, type=str,
                       help="FSDB based threat feed")

    # DATA FEEDS
    # ----------------------------------------------------------------------
    # arguments for the data feeds
    group = parser.add_argument_group("Data feed arguments")
    group.add_argument("-T", "--time-column", default="ts", type=str,
                       help="The time column to read looking for end-time")

    group.add_argument("-m", "--max-records", type=int,
                       help="maximum number of records to return")

    group.add_argument("-b", "--begin-time", default=None, type=str,
                       help="Date to start returning threat feed data from")

    group.add_argument("-e", "--end-time", default=None, type=str,
                       help="Date to stop returning threat feed data after")

    # kafka specific data feed options
    group = parser.add_argument_group("Kafka specific data feed arguments")
    group.add_argument("--data-kafka-servers", default=[], type=str,
                       nargs="*",
                       help="Kafka server to pull data streams from")

    group.add_argument("-t", "--data-topic", default="ssh", type=str,
                       help="Kafka topic to request from the data source")

    group = parser.add_argument_group("BRO specific data feed arguments")
    # BRO file
    group.add_argument("--bro-data", type=str,
                       help="Bro file to read data from")

    group = parser.add_argument_group("File/FSDB specific data feed arguments")
    # fsdb data specific options
    group.add_argument("--fsdb-data", default=None, type=str,
                       help="FSDB data file for testing")

    group = parser.add_argument_group("Output formatting arguments")
    # OUTPUT
    # ----------------------------------------------------------------------
    # output processing
    group.add_argument("-f", "--fields", default=None, type=str, nargs="*",
                       help="Fields to print")

    group.add_argument("--fsdb", action="store_true",
                       help="Output FSDB formatted data")

    group.add_argument("-o", "--output-pattern", default=None, type=str,
                       help="Output a pattern of files instead of stdout; " +
                       "include %%d for a count")

    group.add_argument("-j", "--jinja-template", default=None, type=str,
                       help="Jinja template to use when generating reports")

    group.add_argument("-J", "--jinja-extra-information", default=None,
                       type=str,
                       help="""Extra information in YAML format to
                        include with report generation in 'extra' an field""")
    parser.add_argument("--threads", default=1, type=int,
                        help="Number of output stream threads to create.")

    # Configuration
    group = parser.add_argument_group("Global configuration")
    group.add_argument("-y", "--config", type=argparse.FileType("r"),
                       help="A YAML configuration file specifying"
                       + " all modules to be loaded")
    group.add_argument("-Y", "--config-parameters", type=str, nargs="*",
                       default=[],
                       help="""A list of parameters to pass to the YAML
                       config as jinja template variables.  The parameters
                       should be in the form of name=value pairings""")

    # DEBUGGING
    group = parser.add_argument_group("Debugging arguments")
    group.add_argument("--dump-threat-feed", action="store_true",
                       help="Simply dump the threat feed data to stdout")

    group.add_argument("--dump-data", action="store_true",
                       help="Simply dump all the data without " +
                       "searching to stdout")

    group.add_argument("--dump-events", action="store_true",
                       help="Simply dump all the event data in raw form")

    group.add_argument("--config-templates", action="store_true",
                       help="Dump all module configuration options")

    group.add_argument("-V", "--verbose", action="store_true",
                       help="Verbose/Debugging output")

    args = parser.parse_args()
    if args.verbose:
        global debug
        debug = True

    if args.config_templates:
        loader.dump_config_options(debug)

    # if args.merge_grep and not args.merge_key:
    #     raise ValueError("--merge-key/-k is required with --merge-grep")

    return args


def verbose(number, msg=None):
    if not msg:
        msg = number
        number = ""
    else:
        msg = "ps " + str(number) + ": " + msg

    if debug:
        print(msg)


def get_threat_feed(number, args, conf=None, max_records=None, dump=False):
    """Read in the threat feed stream as a data source to search for"""

    threat_source = loader.create_instance_for_module(conf,
                                                      loader.THREATSOURCE_KEY)

    verbose(number, "created threat feed: " + str(threat_source))

    # initialize and read
    threat_source.open()
    (search_data, search_index) = threat_source.read(max_records)

    verbose(number, "  read feed with " + str(len(search_data)) + " entries")

    if dump:
        import json
        print(json.dumps(search_data))
        print(json.dumps(search_index))
        exit(0)

    return (threat_source, search_data, search_index)


def get_data_source(number, args, conf=None):
    """Get the data source and open it for traversing"""

    data_source = loader.create_instance_for_module(conf,
                                                    loader.DATASOURCE_KEY)

    verbose(number, "created data feed: " + str(data_source))

    # just print it?
    if args.dump_data:
        import json
        for finding in data_source:
            print(json.dumps(data_source.convert_row_to_utf8(finding)))
        exit(0)

    return data_source


def get_searcher(number, args, search_index, data_source, conf=None):
    """Create a searcher object"""
    # create the searching interface
    searcher = loader.create_instance_for_module(conf, loader.SEARCHER_KEY,
                                                 [search_index, data_source,
                                                  data_source.is_binary()])
    verbose(number, "created searcher: " + str(searcher))

    return searcher


def get_outputs(number, conf):
    """Create the output-er object"""

    outputs = []
    section = conf[loader.REPORTER_KEY]

    if type(section) is not list:
        section = [section]

    for item in section:
        obj = loader.create_instance(item, loader.REPORTER_KEY)
        outputs.append(obj)

    return outputs


def get_enrichments(number, conf, search_index, data_source):
    if loader.ENRICHMENT_KEY not in conf:
        return []
    section = conf[loader.ENRICHMENT_KEY]
    enrichers = []

    for item in section:
        enricher = loader.create_instance(item, loader.ENRICHMENT_KEY,
                                          [search_index, data_source,
                                           data_source.is_binary(), loader])
        enrichers.append(enricher)
    return enrichers


def found_event(found_queue, enrichers, outputs):
    while True:
        event = found_queue.get()
        if event is None:
            break  # None in queue signals an exit

        row = event['row']
        match = event['match']
        count = event['count']

        enrichment_data = {}

        # gather enrichment data from the backends
        for ecount, enricher in enumerate(enrichers):
            try:
                (key, result) = enricher.gather(count, row,
                                                match, enrichment_data)
                if key and result:
                    enrichment_data[key] = result
            except Exception as e:
                sys.stderr.write("An enricher failed: " + str(e) + "\n")
                sys.stderr.write("".join(traceback.format_exc()))
                sys.stderr.write(str(enricher.get_config()) + "\n")
                if 'errors' not in enrichment_data:
                    enrichment_data['errors'] = []
                enrichment_data['errors'].append(
                    {'count': count,
                     'module': type(enricher),
                     'msg': 'An enrichment module failed to load data'})

        # loop through the outputs to create stuff
        for output in outputs:
            try:
                outh = output.new_output(count,
                                         row=row,
                                         match=match)
                output.write(count, row, match, enrichment_data, outh)
                output.maybe_close_output(outh)

            except Exception as e:
                sys.stderr.write("The output module failed: " + str(e) + "\n")
                sys.stderr.write("".join(traceback.format_exc()))

        # signal this entry is done
        found_queue.task_done()


def convert_args_to_config(args):
    subconf = {}

    # ----- threat feed
    # read in the threat feed stream as a data source to search for
    conf_part = {}
    if args.threat_fsdb:
        conf_part = {'module': 'fsdb',
                     'file': args.threat_fsdb}
    elif args.threat_kafka_servers:
        conf_part = {'module': 'kafka',
                     'bootstrap_servers': args.threat_kafka_servers,
                     'begin_time': args.threat_begin_time,
                     'topic': args.threat_kafka_topic,
                     'partition': 0,
                     'timeout': args.threat_timeout}
    else:
        raise ValueError("no data source specified")

    subconf[loader.THREATSOURCE_KEY] = conf_part

    # ----- data source
    conf_part = {}
    if args.fsdb_data:
        conf_part = {'module': 'fsdb',
                     'file': args.fsdb_data}
    elif args.bro_data:
        conf_part = {'module': 'bro',
                     'file': args.bro_data}
    elif args.data_kafka_servers:
        conf_part = {'module': 'kafka',
                     'bootstrapservers': args.data_kafka_servers,
                     'begin_time': args.begin_time,
                     'topic': args.data_topic}
    else:
        raise ValueError("no data source specified")
    subconf[loader.DATASOURCE_KEY] = conf_part

    # ----- searcher
    conf_part = {}
    if args.data_topic in ['ssh', 'http']:
        conf_part = {'module': args.data_topic}
    elif args.data_topic in ['ip', 'conn']:
        conf_part = {'module': 'ip'}
    else:
        raise ValueError("no searcher specified")

    subconf[loader.SEARCHER_KEY] = conf_part

    # ----- outputs
    conf_part = {}
    if args.dump_events:
        conf_part = {'module': 'dumper',
                     'stream': args.output_pattern}
    elif args.jinja_template:
        conf_part = {'module': 'reporter',
                     'stream': args.output_pattern,
                     'template': args.jinja_template,
                     'extra_information': args.jinja_extra_information}
    else:
        conf_part = {'module': 'reporter'}  # default
    subconf = [loader.REPORTER_KEY] = conf_part

    conf = {loader.YAML_KEY: [subconf]}
    return conf


def launch_process(combination, args, number):
    """Creates a process to handle a given threat-search configuration entry"""
    # pass in verbosity level
    if args.verbose:
        for subsection in combination:
            item = combination[subsection]
            if type(item) == list:
                for i in item:
                    i['verbose'] = True
            else:
                item['verbose'] = True

    (threat_source, search_data, search_index) = \
        get_threat_feed(number, args, combination,
                        args.threat_max_records, args.dump_threat_feed)

    data_source = get_data_source(number, args, combination)
    searcher = get_searcher(number, args, search_index,
                            data_source, combination)

    data_source.open()

    enrichers = get_enrichments(number, combination, search_index, data_source)

    outputs = get_outputs(number, combination)
    verbose(number, "created outputs: " + str(outputs))

    # loop through all the data for matches
    if debug:
        print("reports created: 0", end="\r")

    # create threads to handle the results
    event_queue = queue.Queue()
    output_threads = []
    for i in range(args.threads):
        thread = threading.Thread(target=found_event,
                                  args=(event_queue, enrichers, outputs))
        thread.start()
        output_threads.append(thread)

    # loop through the outputs of the searcher and create reports
    for count, results in enumerate(searcher):
        row, match = results

        event_queue.put(
            {'row': deepcopy(row),
             'match': deepcopy(match),
             'count': count})

        if debug:
            print("%d: events found: %d" % (number, count+1), end="\r")

        if args.max_records and count >= args.max_records:
            break

    # tell the threads to quit
    for n in range(args.threads):
        event_queue.put(None)

    # wait for threads to clear
    for t in output_threads:
        t.join()


def main():
    # create our loading class
    global loader
    loader = Loader()

    args = parse_args()

    if args.config:
        conf = loader.load_yaml_config(args.config, args.config_parameters)
    else:
        conf = convert_args_to_config

    threat_conf = conf[loader.YAML_KEY]

    processes = []

    if len(threat_conf) == 1:
        # don't bother with all that subprocessing
        launch_process(threat_conf[0], args, 0)
        verbose("")
        return

    for number, combination in enumerate(threat_conf):
        subprocess = multiprocessing.Process(target=launch_process,
                                             args=(combination, args, number))
        subprocess.start()
        processes.append(subprocess)

    for process in processes:
        process.join()
    verbose("")


if __name__ == "__main__":
    main()
