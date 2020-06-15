#!/usr/bin/python3

"""Reads a gawseed-threat-feed pickle file and pipes it to a reporter
for generating reports from archived data"""

import pickle
from gawseed.threatfeed.loader import Loader

import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="""Reads a gawseed-threat-feed pickle file and pipes it to a reporter for generating reports from archived data""")

    parser.add_argument("-j", "--jinja-template", default=None, type=str,
                        help="The jinja template to use when generating reports")

    parser.add_argument("-J", "--jinja-extra-information", default=None, type=str,
                        help="Extra information in YAML format to include with report generation in 'extra' an field")

    parser.add_argument("--json", default=None, type=argparse.FileType('rb'),
                        help="An extra json file to read")

    parser.add_argument("--json-extra-name", default="test", type=str,
                        help="The tag name to load the json data into")

    parser.add_argument("pickle_file", type=argparse.FileType('rb'),
                        nargs='?', default=sys.stdin,
                        help="The input pickle archive file to load")

    args = parser.parse_args()

    if not args.jinja_template:
        raise ValueError("-j is a required argument")

    return args

def main():
    args = parse_args()

    data = pickle.loads(args.pickle_file.read())
    conf = { 'module': 'reporter',
             'template': args.jinja_template,
             'extra_information': args.jinja_extra_information}

    if args.json:
        import json
        data[args.json_extra_name] = json.loads(args.json.read())
        data['enrichments'][args.json_extra_name] = data[args.json_extra_name]

    loader = Loader()
    reporter = loader.create_instance(conf, loader.REPORTER_KEY)
    reporter.new_output(0)
    reporter.write(0, data['row'], data['match'], data['enrichments'])
    reporter.maybe_close_output()

if __name__ == "__main__":
    main()

