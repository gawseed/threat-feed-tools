#!/usr/bin/python3

"""This is a generic threat-feed searching application that takes a
threat feed of various types and matches it against sources of network
log data to search through.  It can take both threat-feeds and log
data from multiple sources, including kafka and files.  It's output is
configurable and can be given a jinja2 template for generic report
generation.
"""

import sys, os
import re

import datetime
import yaml
import importlib

import sys
import time
import argparse
from msgpack import unpackb

from gawseed.threatfeed import loader

debug = False

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="This uses data from threat feeds (in kafka topics or files) to search through network data (from kafka or files) and reports any matches as 'events'.")

    # THREAT FEEDS
    # ----------------------------------------------------------------------
    # arguments for the threat feed source
    group = parser.add_argument_group("Threat feed arguments")
    group.add_argument("-B", "--threat-begin-time", default=None, type=str,
                        help="Date to start returning threat feed data from")

    group.add_argument("-E", "--threat-end-time", default=None, type=str,
                        help="Date to stop returning threat feed data after")

    group.add_argument("-M", "--threat-max-records", default=None, type=int,
                        help="Maximum number of threat records to retrieve and search for ")

    group.add_argument("--threat-timeout", default=1000, type=int,
                        help="Maximum number of ms to wait for a threat feed before figuring its done")


    # arguments for kafka threat feeds
    group = parser.add_argument_group("Kafka specific threat feed arguments")
    group.add_argument("-K", "--threat-kafka-servers", default=[], type=str,
                        nargs="*", help="Kafka server to pull topics from")

    group.add_argument("--threat-kafka-topic", default="gawseed_ipaddresses", type=str,
                        help="The kafka threat topic to use as the threat source")

    group = parser.add_argument_group("File/FSDB specific threat feed arguments")
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
                        nargs="*", help="Kafka server to pull data streams from")

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
                        help="Output a pattern of files instead of stdout; include %%d for a count")

    group.add_argument("-j", "--jinja-template", default=None, type=str,
                        help="The jinja template to use when generating reports")

    group.add_argument("-J", "--jinja-extra-information", default=None, type=str,
                        help="Extra information in YAML format to include with report generation in 'extra' an field")

    # Configuration
    group = parser.add_argument_group("Global configuration")
    group.add_argument("-y", "--config", type=argparse.FileType("r"),
                       help="A YAML configuration file specifying all modules to be loaded")

    # DEBUGGING
    group = parser.add_argument_group("Debugging arguments")
    group.add_argument("--dump-threat-feed", action="store_true",
                        help="Simply dump the threat feed data to stdout")
   
    group.add_argument("--dump-data", action="store_true",
                        help="Simply dump all the data without searching to stdout")

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
        dump_config_options(args)

    # if args.merge_grep and not args.merge_key:
    #     raise ValueError("--merge-key/-k is required with --merge-grep")

    return args

def verbose(msg):
    if debug:
        print(msg)

def get_threat_feed(args, conf=None):
    """Read in the threat feed stream as a data source to search for"""

    # read in the threat feed stream as a data source to search for
    if not conf:
        if args.threat_fsdb:
            conf_part = { 'module': 'fsdb',
                          'file': args.threat_fsdb}
        elif args.threat_kafka_servers:
            conf_part = { 'module': 'kafka',
                          'bootstrap_servers': args.threat_kafka_servers,
                          'begin_time': args.threat_begin_time,
                          'topic': args.threat_kafka_topic,
                          'partition': 0,
                          'timeout': args.threat_timeout}
        else:
            raise ValueError("no data source specified")

        conf = { loader.YAML_KEY: [{loader.THREATSOURCE_KEY: conf_part}] }

    threat_source = loader.create_instance(conf, loader.THREATSOURCE_KEY)

    verbose("created threat feed: " + str(threat_source))

    # initialize and read
    threat_source.initialize()
    threat_source.open()
    (search_data, search_index) = threat_source.read(args.threat_max_records)

    verbose("  read feed with " + str(len(search_data)) + " entries")

    if args.dump_threat_feed:
        print(search_data)
        print(search_index)
        exit(0)

    return (threat_source, search_data, search_index)


def get_data_source(args, conf=None):
    """Get the data source and open it for traversing"""
    if not conf:
        if args.fsdb_data:
            conf_part = { 'module': 'fsdb',
                          'file': args.fsdb_data }
        elif args.bro_data:
            conf_part = { 'module': 'bro',
                          'file': args.bro_data }
        elif args.data_kafka_servers:
            conf_part = { 'module': 'kafka',
                          'bootstrapservers': args.data_kafka_servers,
                          'begin_time': args.begin_time,
                          'topic': args.data_topic }
        else:
            raise ValueError("no data source specified")
        conf = { loader.YAML_KEY: [{loader.DATASOURCE_KEY: conf_part}] }

    data_source = loader.create_instance(conf, loader.DATASOURCE_KEY)

    data_source.initialize()

    verbose("created data feed: " + str(data_source))
    data_source.open()

    # just print it?
    if args.dump_data:
        for finding in data_source:
            print(finding)
        exit(0)

    return data_source

def get_searcher(args, search_index, data_source, conf=None):
    """Create a searcher object"""
    # create the searching interface
    if not conf:
        if args.data_topic in ['ssh', 'http']:
            conf_part = {'module': args.data_topic}
        elif args.data_topic in ['ip', 'conn']:
            conf_part = {'module': 'ip'}
        else:
            raise ValueError("no searcher specified")

        conf = { loader.YAML_KEY: [{loader.SEARCHER_KEY: conf_part}] }

    searcher = loader.create_instance(conf, loader.SEARCHER_KEY,
                                      [data_iterator, data_source.is_binary()])
    searcher.initialize()
    
    verbose("created searcher: " + str(searcher))

    return searcher

def get_output(conf):
    """Create the output-er object"""
    if not conf:
        if args.dump_events:
            conf_part = {'module': 'dumper',
                         'stream': args.output_pattern}
        elif args.jinja_template:
            conf_part = {'module': 'reporter',
                         'stream': args.output_pattern,
                         'template': args.jinja_template,
                         'extra_information': args.jinja_extra_information
            }
        else:
            conf_part = {'module': 'reporter' } # default
        conf = { loader.YAML_KEY: [{loader.SEARCHER_KEY: conf_part}] }
        
    output = loader.create_instance(conf, loader.REPORTER_KEY)
    output.initialize()

    return output

def get_enrichments(conf, search_index, data_source):
    if ENRICHMENT_KEY not in conf[YAML_KEY][0]:
        return []
    section = conf[YAML_KEY][0][ENRICHMENT_KEY]
    enrichers = []
    for item in section:
        obj = item['class']
        enricher = obj(item, search_index, data_source, data_source.is_binary())
        enricher.initialize()
        enrichers.append(enricher)
    return enrichers

def main():
    args = parse_args()

    conf = None
    if args.config:
        conf = loader.load_yaml_config(args.config)

    (threat_source, search_data, search_index) = get_threat_feed(args, conf)
    data_source = get_data_source(args, conf)
    searcher = get_searcher(args, search_index, data_source, conf)

    enrichers = get_enrichments(conf, search_index, data_source)

    output = get_output(conf)
    verbose("created output: " + str(output))

    # loop through all the data for matches
    if debug:
        print("reports created: 0", end="\r")

    for count, finding in enumerate(next(searcher)):
        enrichment_data = {}

        # gather enrichment data from the backends
        for ecount, enricher in enumerate(enrichers):
            try:
                (key, result) = enricher.gather(count, finding[0], finding[1])
                enrichment_data[key] = result
            except Exception as e:
                sys.stderr.write("An enricher failed: " + str(e))
                if 'errors' not in enrichment_data:
                    enrichment_data['errors'] = []
                enrichment_data['errors'].append({ 'count': count,
                                                   'module': type(enricher),
                                                   'msg': 'An enrichment module failed to load data'})

        try:
            output.new_output(count)
            output.write(count, finding[0], finding[1], enrichment_data)
            output.maybe_close_output()
        except Exception as e:
            sys.stderr.write("The output module failed: " + str(e))

        if debug:
            print("reports created: %d" % (count), end="\r")

        if args.max_records and count >= args.max_records:
            break

    verbose("")

if __name__ == "__main__":
    main()
