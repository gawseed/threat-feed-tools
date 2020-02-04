"""Utilities for dynamically loading python modules for specific functions,
   parsing yaml config files and loading needed modules"""

import yaml
import importlib

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
        'url': 'gawseed.threatfeed.enrichments.EnrichmentURL',
        'datasource': 'gawseed.threatfeed.enrichments.datasource.Datasource',
    },
}

def dump_config_options(debug=False):
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
    
def load_module_name(module_name):
    """Given a module name, split it in parts, load the module and find its child name
    within and return the final loaded object"""
    try:
        lastdotnum = module_name.rindex('.')
        modulename = module_name[:lastdotnum]   # just the module name
        class_name = module_name[lastdotnum+1:] # just the class init function name

        module = importlib.import_module(modulename)
    except Exception as e:
        print(e)
        raise ValueError("Error parsing/loading module/class name: " + module_name)

    if not hasattr(module, class_name):
        raise ValueError("Error finding class name '" + class_name + "' in module '" + module + "'")

    return getattr(module, class_name)

def load_and_create_module(module_name, config_section):
    """Loads a module/class and then creates an instance and returns it"""
    obj = conf['class']

def load_yaml_config(config_stream):
    """Loads a yaml config from a specific stream and loads class definitions based on it."""

    conf = yaml.load(config_stream, Loader=yaml.FullLoader)
    load_class_config(conf[YAML_KEY])
    return conf

def load_class_config(threatconfs, sections=YAML_SECTIONS):
    """Loops through config and loads classes for each one into a 'class' key"""

    # load each section
    for threatconf in threatconfs:
        for section in sections:
            if section in threatconf: # some are optional
                parts = threatconf[section]
                if type(parts) != list:
                    parts = [parts]
                for part in parts:
                    module = part['module']
                    if module in module_xforms[section]:
                        module = module_xforms[section][module]
                    part['class'] = load_module_name(module)

    return threatconf

def create_instance(conf, module_type, args=[], initialize=True):
    if 'class' not in conf[YAML_KEY][0][module_type]:
        load_class_config(conf[YAML_KEY], [module_type])
    
    obj = conf[YAML_KEY][0][module_type]['class']

    created = obj(conf[YAML_KEY][0][module_type], *args)

    if initialize:
        created.initialize()

    return created

