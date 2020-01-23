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

from gawseed.threatfeed.feeds.kafka import KafkaThreatFeed
from gawseed.threatfeed.feeds.fsdb import FsdbThreatFeed

from gawseed.threatfeed.datasources.kafka import KafkaDataSource
from gawseed.threatfeed.datasources.fsdb import FsdbDataSource
from gawseed.threatfeed.datasources.bro import BroDataSource

from gawseed.threatfeed.search.ip import IPSearch
from gawseed.threatfeed.search.http import HTTPSearch
from gawseed.threatfeed.search.ssh import SSHSearch

from gawseed.threatfeed.events.printer import EventStreamPrinter
from gawseed.threatfeed.events.dumper import EventStreamDumper
from gawseed.threatfeed.events.reporter import EventStreamReporter

YAML_KEY='threat-search'
THREATSOURCE_KEY='threatsource'
DATASOURCE_KEY='datasource'
SEARCHER_KEY='searcher'
REPORTER_KEY='reporter'
ENRICHMENT_KEY='enrichments'
YAML_SECTIONS=[THREATSOURCE_KEY, DATASOURCE_KEY, SEARCHER_KEY, REPORTER_KEY, ENRICHMENT_KEY]

# load modules?
module_xforms = {
    THREATSOURCE_KEY: {
        'kafka': 'gawseed.threatfeed.feeds.kafka.KafkaThreatFeed',
        'fsdb': 'gawseed.threatfeed.feeds.fsdb.FsdbThreatFeed',
    },
    DATASOURCE_KEY: {
        'fsdb': 'gawseed.threatfeed.datasources.fsdb.FsdbDataSource',
        'bro': 'gawseed.threatfeed.datasources.bro.BroDataSource',
        'kafka': 'gawseed.threatfeed.datasources.kafka.KafkaDataSource',
    },
    SEARCHER_KEY: {
        'ssh': 'gawseed.threatfeed.search.ssh.SSHSearch',
        'ip': 'gawseed.threatfeed.search.ip.IPSearch',
        'http': 'gawseed.threatfeed.search.http.HTTPSearch',
        'dns': 'gawseed.threatfeed.search.dns.DNSSearch',
        're': 'gawseed.threatfeed.search.re.RESearch',
    },
    REPORTER_KEY: {
        'dumper': 'gawseed.threatfeed.events.dumper.EventStreamDumper',
        'printer': 'gawseed.threatfeed.events.printer.EventStreamPrinter',
        'reporter': 'gawseed.threatfeed.events.reporter.EventStreamReporter',
    },
    ENRICHMENT_KEY: {
        'url': 'gawseed.threatfeed.enrichments.EnrichmentURL'
    },
}

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

def load_module_name(module_name):
    try:
        lastdotnum = module_name.rindex('.')
        modulename = module_name[:lastdotnum]   # just the module name
        class_name = module_name[lastdotnum+1:] # just the class init function name

        module = importlib.import_module(modulename)
    except:
        raise ValueError("Error parsing/loading module/class name: " + module_name)

    if not hasattr(module, class_name):
        raise ValueError("Error finding class name '" + class_name + "' in module '" + module + "'")

    return getattr(module, class_name)

def dump_config_options(args):
    print("threat-search:")
    first_char="-"
    for part in module_xforms:
        print("  %s %s:" % (first_char, part))
        print("    # ---- %s modules and options" % (part))
        print("    # (pick one module)")
        for module in module_xforms[part]:
            print("      module: %s" % (module))

            try:
                module = load_module_name(module_xforms[part][module])
                # this forces a module to just dump out config settings to stdout
                if module.__doc__:
                    doc = module.__doc__
                    doc = re.sub("\n", "\n      # ", doc)
                    print("      #       " + doc)
                    
                if part == SEARCHER_KEY:
                    x = module(None, None, False, {'dump_config': 1})
                elif part == ENRICHMENT_KEY:
                    x = module({'dump_config': 1}, None, None, False)
                else:
                    x = module({'dump_config': 1})
            except Exception as e:
                print("      # couldn't get config for this")
                if (debug):
                    print("      # " + str(e))
                    

            print("")
            first_char=" "
    exit()
    
def load_yaml_config(args):
    defaults = {
        'threatsource': {
            'module': 'kafka',
            'timeout': 2000,
        },
        'datasource': {
            'module': 'kafka',
            'topic': 'ssh', # XXX don't make this a default?
            'keys': ['id_orig_h']
        },
        'searcher': {
            'module': 'ssh' # XXX same
        },
        'reporter': {
            'module': 'eventReporter',
        }
    }

    conf = yaml.load(args.config, Loader=yaml.FullLoader)
    
    # fill in defaults
    threatconfs = conf[YAML_KEY]
    for threatconf in threatconfs:
        # insert default values if needed
        for key in defaults:
            if key not in threatconf:
                threatconf[key] = {}
            for subkey in defaults[key]:
                if subkey not in threatconf[key]:
                    threatconf[key][subkey] = defaults[key][subkey]

    for threatconf in threatconfs:
        for section in YAML_SECTIONS:
            if section in threatconf: # some are optional
                parts = threatconf[section]
                if type(parts) != list:
                    parts = [parts]
                for part in parts:
                    module = part['module']
                    if module in module_xforms[section]:
                        module = module_xforms[section][module]
                    part['class_name'] = load_module_name(module)

    return conf
        


def get_threat_feed(args, conf=None):
    """Read in the threat feed stream as a data source to search for"""

    # read in the threat feed stream as a data source to search for
    if conf:
        obj = conf[YAML_KEY][0][THREATSOURCE_KEY]['class_name']
        threat_source = obj(conf[YAML_KEY][0][THREATSOURCE_KEY])
    elif args.threat_fsdb:
        threat_source = FsdbThreatFeed(args.threat_fsdb)
    else:
        threat_source = KafkaThreatFeed({'bootstrapservers': args.threat_kafka_servers,
                                         'begintime': args.threat_begin_time,
                                         'topic': args.threat_kafka_topic,
                                         'partition': 0,
                                         'timeout': args.threat_timeout})
    verbose("created threat feed: " + str(threat_source))

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
    if conf:
        obj = conf[YAML_KEY][0][DATASOURCE_KEY]['class_name']
        data_source = obj(conf[YAML_KEY][0][DATASOURCE_KEY])
    elif args.fsdb_data:
        data_source = FsdbDataSource({'file': args.fsdb_data})
    elif args.bro_data:
        data_source = BroDataSource({'file': args.bro_data})
    else:
        data_source = KafkaDataSource({'bootstrapservers': args.data_kafka_servers,
                                       'begin_time': args.begin_time,
                                       'topic': args.data_topic})

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
    if conf:
        obj = conf[YAML_KEY][0][SEARCHER_KEY]['class_name']
        searcher = obj(search_index, data_iterator = data_source, binary_search = data_source.is_binary(), conf=conf[YAML_KEY][0][SEARCHER_KEY])
    elif args.data_topic == 'ssh':
        searcher = SSHSearch(search_index, data_iterator = data_source, binary_search = data_source.is_binary())
    elif args.data_topic == 'ip' or args.data_topic == 'conn':
        searcher = IPSearch(search_index, data_iterator = data_source, binary_search = data_source.is_binary())
    elif args.data_topic == 'http':
        searcher = HTTPSearch(search_index, data_iterator = data_source, binary_search = data_source.is_binary())
        
    searcher.initialize()
    
    verbose("created searcher: " + str(searcher))

    return searcher

def get_enrichments(conf, search_index, data_source):
    if ENRICHMENT_KEY not in conf[YAML_KEY][0]:
        return []
    section = conf[YAML_KEY][0][ENRICHMENT_KEY]
    enrichers = []
    for item in section:
        obj = item['class_name']
        enricher = obj(item, search_index, data_source, data_source.is_binary())
        enricher.initialize()
        enrichers.append(enricher)
    return enrichers

def main():
    args = parse_args()

    conf = None
    if args.config:
        conf = load_yaml_config(args)

    (threat_source, search_data, search_index) = get_threat_feed(args, conf)
    data_source = get_data_source(args, conf)
    searcher = get_searcher(args, search_index, data_source, conf)

    #output = EventStreamDumper() 
    if conf:
        obj = conf[YAML_KEY][0][REPORTER_KEY]['class_name']
        output = obj(conf[YAML_KEY][0][REPORTER_KEY])
    elif args.dump_events:
        output = EventStreamDumper({'stream': args.output_pattern})
    elif args.jinja_template:
        output = EventStreamReporter({'stream': args.output_pattern,
                                      'template': args.jinja_template,
                                      'extra_information': args.jinja_extra_information})
    else:
        output = EventStreamPrinter({'stream': args.output_pattern,
                                     'extra_fields': ['auth_success']}) # auth for ssh
    output.initialize()

    enrichers = get_enrichments(conf, search_index, data_source)

    verbose("created output: " + str(output))

    # loop through all the data for matches
    if debug:
        print("reports created: 0", end="\r")
    for count, finding in enumerate(next(searcher)):
        enrichment_data = {}

        # gather enrichment data from the backends
        for ecount, enricher in enumerate(enrichers):
            (key, result) = enricher.gather(count, finding[0], finding[1])
            enrichment_data[key] = result

        output.new_output(count)
        output.write(count, finding[0], finding[1], enrichment_data)
        output.maybe_close_output()

        if debug:
            print("reports created: %d" % (count), end="\r")

        if args.max_records and count >= args.max_records:
            break

if __name__ == "__main__":
    main()
