#!/usr/bin/python3

import datetime
import yaml

import sys
import time
import argparse
from msgpack import unpackb

# ick, remote during packaging:
import sys, os

from gawseed.threatfeed.feeds.kafka import KafkaThreatFeed
from gawseed.threatfeed.feeds.fsdb import FsdbThreatFeed

from gawseed.threatfeed.datasources.kafka import KafkaDataSource
from gawseed.threatfeed.datasources.fsdb import FsdbDataSource
from gawseed.threatfeed.datasources.bro import BroDataSource

from gawseed.threatfeed.search.http import HTTPSearch
from gawseed.threatfeed.search.ip import IPSearch
from gawseed.threatfeed.search.ssh import SSHSearch

from gawseed.threatfeed.events.printer import EventStreamPrinter
from gawseed.threatfeed.events.dumper import EventStreamDumper

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

    group.add_argument("-t", "--data-topic", default="dns", type=str,
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

    group.add_argument("-j", "--jinja-template", default=None, type=argparse.FileType("r"),
                        help="The jinja template to use when generating reports")

    group.add_argument("-J", "--jinja-extra-information", default=None, type=argparse.FileType("r"),
                        help="Extra information in YAML format to include with report generation in 'extra' an field")

    # DEBUGGING
    group = parser.add_argument_group("Debugging arguments")
    group.add_argument("--dump-threat-feed", action="store_true",
                        help="Simply dump the threat feed data to stdout")
   
    group.add_argument("--dump-data", action="store_true",
                        help="Simply dump all the data without searching to stdout")

    group.add_argument("--dump-events", action="store_true",
                        help="Simply dump all the event data in raw form")

    group.add_argument("-V", "--verbose", action="store_true",
                        help="Verbose/Debugging output")

    args = parser.parse_args()
    if args.verbose:
        global debug
        debug = True

    # if args.merge_grep and not args.merge_key:
    #     raise ValueError("--merge-key/-k is required with --merge-grep")

    return args

def verbose(msg):
    if debug:
        print(msg)

def main():
    args = parse_args()

    #
    # argument/search setup
    #

    # read in the threat feed stream as a data source to search for
    if args.threat_fsdb:
        threat_source = FsdbThreatFeed(args.threat_fsdb)
    else:
        threat_source = KafkaThreatFeed(args.threat_kafka_servers, args.threat_begin_time,
                                          args.threat_kafka_topic)
    verbose("created threat feed: " + str(threat_source))

    threat_source.open()
    (search_data, search_index) = threat_source.read(args.threat_max_records)
    verbose("  read feed with " + str(len(search_data)) + " entries")

    if args.dump_threat_feed:
        print(search_data)
        print(search_index)
        exit(0)

    # open the datasource
    if args.fsdb_data:
        data_source = FsdbDataSource(file=args.fsdb_data)
    elif args.bro_data:
        data_source = BroDataSource(file=args.bro_data)
    else:
        data_source = KafkaDataSource(args.data_kafka_servers,
                                      begin_time = args.begin_time,
                                      topic=args.data_topic)

    verbose("created data feed: " + str(data_source))
    data_source.open()

    # just print it?
    if args.dump_data:
        for finding in data_source:
            print(finding)
        exit(0)

    # create the searching interface
    if args.data_topic == 'ssh':
        searcher = SSHSearch(search_index, data_iterator = data_source, binary_search = data_source.is_binary())
    elif args.data_topic == 'http':
        searcher = HTTPSearch(search_index, data_iterator = data_source, binary_search = data_source.is_binary())
        

    verbose("created searcher: " + str(searcher))

    #output = EventStreamDumper() 
    if args.dump_events:
        output = EventStreamDumper(stream=args.output_pattern)
    elif args.jinja_template:
        output = EventStreamReporter(stream=args.output_pattern,
                                     jinja_template=args.jinja_template,
                                     jinja_extra_information=args.jinja_extra_information)
    else:
        output = EventStreamPrinter(stream=args.output_pattern,
                                    extra_fields=['auth_success']) # auth for ssh

    verbose("created output: " + str(output))

    # loop through all the data for matches
    for count, finding in enumerate(next(searcher)):
        output.new_output(count)
        output.write(count, finding[0], finding[1])
        output.maybe_close_output()
        if args.max_records and count >= args.max_records:
            break

if __name__ == "__main__":
    main()
