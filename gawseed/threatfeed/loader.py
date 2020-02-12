"""Utilities for dynamically loading python modules for specific functions,
   parsing yaml config files and loading needed modules"""

import importlib
import re
import yaml

YAML_KEY = 'threat-search'
THREATSOURCE_KEY = 'threatsource'
DATASOURCE_KEY = 'datasource'
SEARCHER_KEY = 'searcher'
REPORTER_KEY = 'reporter'
ENRICHMENT_KEY = 'enrichments'
YAML_SECTIONS = [THREATSOURCE_KEY, DATASOURCE_KEY, SEARCHER_KEY, REPORTER_KEY, ENRICHMENT_KEY]

# load modules?
MODULE_XFORMS = {
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

named_entries = {}

def dump_config_options(debug=False):
    print("threat-search:")
    first_char = "-"
    for part in MODULE_XFORMS:
        print("  %s %s:" % (first_char, part))
        print("    # ---- %s modules and options" % (part))
        print("    # (pick one module)")
        for module in MODULE_XFORMS[part]:
            print("      module: %s" % (module))

            try:
                module = load_module_name(MODULE_XFORMS[part][module])
                # this forces a module to just dump out config settings to stdout
                if module.__doc__:
                    doc = module.__doc__
                    doc = re.sub("\n", "\n      # ", doc)
                    print("      #       " + doc)
                    
                if part == SEARCHER_KEY:
                    module({'dump_config': 1}, None, None, False)
                elif part == ENRICHMENT_KEY:
                    module({'dump_config': 1}, None, None, False)
                else:
                    module({'dump_config': 1})
            except Exception as e:
                print("      # couldn't get config for this")
                if debug:
                    print("      # " + str(e))
                    

            print("")
            first_char = " "
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
                    if module in MODULE_XFORMS[section]:
                        module = MODULE_XFORMS[section][module]
                    part['class'] = load_module_name(module)

    return threatconf

def maybe_save_entry(conf):
    """Remembers a named configuration template for use later"""
    global named_entries

    if 'name' not in conf:
        return

    entry_name = conf['name']
    named_entries[entry_name] = dict(conf)
    del named_entries[entry_name]['name']
    
def copy_entry(entry_name, conf):
    """Creates a new configuration dictionary based on a named template and override values."""
    if entry_name not in named_entries:
        return conf

    # clone the template source
    newconf = dict(named_entries[entry_name])

    # add/override other variables
    for item in conf:
        newconf[item] = conf[item]

    return newconf

def create_instance(conf, module_type, args=[], initialize=True):
    """Creates an instantiated instance of a threat-feed module"""

    # save this if requested
    maybe_save_entry(conf)
        
    # if they've requested a template
    if 'use' in conf:
        conf = copy_entry(conf['use'], conf)

    if 'class' not in conf[YAML_KEY][0][module_type]:
        load_class_config(conf[YAML_KEY], [module_type])
    
    obj = conf[YAML_KEY][0][module_type]['class']

    created = obj(conf[YAML_KEY][0][module_type], *args)

    if initialize:
        created.initialize()

    return created

