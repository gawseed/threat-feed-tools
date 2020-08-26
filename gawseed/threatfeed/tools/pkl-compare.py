#!/usr/bin/python3

import pickle
import pprint

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, FileType
import sys

def parse_args():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            description=__doc__,
	                        epilog="Exmaple Usage: pkl-compare [file1, ...]")

    parser.add_argument("-c", "--comparison-records", type=str, nargs="+",
                        default=[],
                        help="Comparison records to use")

    parser.add_argument("-d", "--dump-pkls", action="store_true",
                        help="Just output a pprinted version of the pkl files")

    parser.add_argument("input_file", type=FileType('rb'), nargs="+",
                        help="Input pkl files to read from")

    args = parser.parse_args()

    if not args.dump_pkls and len(args.comparison_records) == 0:
        raise ValueError("At least one comparison record type must be passed to -c")
    return args

def main():
    args = parse_args()

    # read in the results into a file
    results = []
    for infile in args.input_file:
        results.append(pickle.load(infile))

    # just print them?
    if args.dump_pkls:
        pprint.pprint(results)
        sys.exit()

    # process the request comparisons into chunks
    comparisons = [x.split('.') for x in args.comparison_records]
    print(comparisons)
    
    table_results={}
    for record in results:
        values=[]
        for comparison in comparisons:

            # collect the value from the nested structure
            value = record
            for item in comparison:
                value = value[item]
            values.append(value)

        # descend the tree creating spots as needed
        spot = table_results
        for value in values:
            if value not in spot:
                spot[value] = {}
            spot = spot[value]

        if 'ans' not in spot:
            spot['ans'] = 0
        spot['ans'] += 1

    pprint.pprint(table_results)

if __name__ == "__main__":
    main()
