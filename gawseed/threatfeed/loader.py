import importlib
import re
import yaml
import traceback
import jinja2

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
        'json': 'gawseed.threatfeed.datasources.json.JsonDataSource',
        'kafka': 'gawseed.threatfeed.datasources.kafka.KafkaDataSource',
        'druid': 'gawseed.threatfeed.datasources.druid.DruidDataSource',
    },
    SEARCHER_KEY: {
        'keys': 'gawseed.threatfeed.search.keys.KeysSearch',
        'ip': 'gawseed.threatfeed.search.ip.IPSearch',
        'iprange': 'gawseed.threatfeed.search.iprange.IPRangeSearch',
        'ssh': 'gawseed.threatfeed.search.ssh.SSHSearch',
        'http': 'gawseed.threatfeed.search.http.HTTPSearch',
        'dns': 'gawseed.threatfeed.search.dns.DNSSearch',
        're': 'gawseed.threatfeed.search.re.RESearch',
        'parallel': 'gawseed.threatfeed.search.parallel.Parallel',
    },
    REPORTER_KEY: {
        'dumper': 'gawseed.threatfeed.events.dumper.EventStreamDumper',
        'printer': 'gawseed.threatfeed.events.printer.EventStreamPrinter',
        'reporter': 'gawseed.threatfeed.events.reporter.EventStreamReporter',
        'archiver': 'gawseed.threatfeed.events.archiver.ArchiveReporter',
        'misp': 'gawseed.threatfeed.events.misp.EventMisp',
        'summarizer': 'gawseed.threatfeed.events.summarizer.Summarizer',
        'multisummarizer': 'gawseed.threatfeed.events.multisummarizer.MultiSummarizer',
    },
    ENRICHMENT_KEY: {
        'url': 'gawseed.threatfeed.enrichments.EnrichmentURL',
        'datasource': 'gawseed.threatfeed.enrichments.datasource.Datasource',
        'sorter': 'gawseed.threatfeed.enrichments.sorter.EnrichmentSort',
        'summarizer': 'gawseed.threatfeed.enrichments.summarizer.Summarizer',
        'dnssummarizer': 'gawseed.threatfeed.enrichments.dnssummarizer.DNSSummarizer',
        'connectioncounter': 'gawseed.threatfeed.enrichments.connectionCounter.ConnectionCounter',
        'connectiongrapher': 'gawseed.threatfeed.enrichments.connectionGrapher.ConnectionGrapher',
        'similaripsgraph': 'gawseed.threatfeed.enrichments.similarIPsGraph.SimilarIPsGraph',
        'prioritytotal': 'gawseed.threatfeed.enrichments.priorityTotal.PriorityTotal',
    },
}

class Loader():
    YAML_KEY = YAML_KEY
    THREATSOURCE_KEY = THREATSOURCE_KEY
    DATASOURCE_KEY = DATASOURCE_KEY
    SEARCHER_KEY = SEARCHER_KEY
    REPORTER_KEY = REPORTER_KEY
    ENRICHMENT_KEY = ENRICHMENT_KEY
    YAML_SECTIONS = YAML_SECTIONS
    MODULE_XFORMS = MODULE_XFORMS

    def __init__(self):
        self._named_entries = {}

    def dump_config_options(self, debug=False):
        print("threat-search:")
        first_char = "-"
        for part in MODULE_XFORMS:
            print("  %s %s:" % (first_char, part))
            print("    # ---- %s modules and options" % (part))
            print("    # (pick one module)")
            for module in MODULE_XFORMS[part]:
                print("      module: %s" % (module))

                try:
                    module = self.load_module_name(MODULE_XFORMS[part][module])
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
                        print(traceback.format_exc())
                        

                print("")
                first_char = " "
        exit()
        
    def load_module_name(self, module_name):
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
            raise ValueError("Error finding class name '" + str(class_name) + "' in module '" + str(module) + "'")

        return getattr(module, class_name)

    def load_yaml_config(self, config_stream, config_parameters):
        """Loads a yaml config from a specific stream and loads class definitions based on it."""

        config_vars = {}
        for item in config_parameters:
            try:
                (name, value) = item.split("=")
                config_vars[name] = value
            except:
                raise ValueError("illegal parameter/syntax passed: {param}".format(item))

        conf_data = config_stream.read()
        template = jinja2.Environment(loader=jinja2.FileSystemLoader("./")).from_string(conf_data)

        conf_data = template.render(config_vars)
        conf = yaml.load(conf_data, Loader=yaml.FullLoader)
        
        self.load_class_configs(conf[YAML_KEY])
        return conf

    def load_class_config(self, section, part):
        module = part['module']
        if module in MODULE_XFORMS[section]:
            module = MODULE_XFORMS[section][module]
        part['class'] = self.load_module_name(module)

    def load_class_configs(self, threatconfs, sections=YAML_SECTIONS):
        """Loops through config and loads classes for each one into a 'class' key"""

        # load each section
        for threatconf in threatconfs:
            for section in sections:
                if section in threatconf: # some are optional
                    parts = threatconf[section]
                    if type(parts) != list:
                        parts = [parts]
                    for part in parts:
                        self.load_class_config(section, part)

        return threatconf

    def maybe_save_entry(self, conf):
        """Remembers a named configuration template for use later"""
        if 'name' not in conf:
            return

        entry_name = conf['name']
        self._named_entries[entry_name] = dict(conf)
        del self._named_entries[entry_name]['name']
        
    def copy_entry(self, entry_name, conf):
        """Creates a new configuration dictionary based on a named template and override values."""
        if entry_name not in self._named_entries:
            return conf

        # clone the template source
        newconf = dict(self._named_entries[entry_name])

        # add/override other variables
        for item in conf:
            newconf[item] = conf[item]

        return newconf

    def create_instance(self, subconf, module_type, args=[], initialize=True):
        """Creates an instantiated instance of a threat-feed module"""

        # save this if requested
        self.maybe_save_entry(subconf)
            
        # if they've requested a template
        if 'use' in subconf:
            subconf = self.copy_entry(subconf['use'], subconf)

        if 'class' not in subconf:
            self.load_class_config(module_type, subconf)
        
        obj = subconf['class']

        created = obj(subconf, *args)

        if initialize:
            created.initialize()

        return created


    def create_instance_for_module(self, conf, module_type, args=[], initialize=True):
        subconf = conf[module_type]
        return self.create_instance(subconf, module_type, args, initialize)
