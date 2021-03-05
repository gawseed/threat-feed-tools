#!/usr/bin/python3

"""Reads a gawseed-threat-feed pickle file and pipes it to a misp submission
object for submitting to a misp instance"""

import pickle
from gawseed.threatfeed.loader import Loader, MODULE_XFORMS, REPORTER_KEY

import argparse
import sys

def parse_args():

    reporters = list(MODULE_XFORMS[REPORTER_KEY].keys())

    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     description=__doc__)

    parser.add_argument("-u", "--misp-url", type=str,
                        help="MISP url to connect to")

    parser.add_argument("-k", "--misp-key", type=str,
                        help="MISP key to use")

    parser.add_argument("-e", "--extra-information", default=None, type=str,
                        help="Extra information in YAML format to include labeling the feed information.")

    parser.add_argument("-U", "--web-report-urls", type=str, nargs="*",
                        help="Web report URL to add as an attribute")



    parser.add_argument("pickle_file", type=argparse.FileType('rb'),
                        nargs='?', default=sys.stdin,
                        help="The input pickle archive file to load")

    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    data = pickle.loads(args.pickle_file.read())
    conf = {'module': 'misp',
            'url': args.misp_url,
            'key': args.misp_key,
            'extra_information': args.extra_information,
            'web_report_urls': args.web_report_urls}

    loader = Loader()

    misp = loader.create_instance(conf, loader.REPORTER_KEY)
    misp.write(0, data['row'], data['match'], data['enrichments'])
    misp.maybe_close_output()


if __name__ == "__main__":
    main()

