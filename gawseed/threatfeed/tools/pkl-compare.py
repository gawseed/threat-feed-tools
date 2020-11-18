#!/usr/bin/python3

import sys
import os

import pickle
import pprint
import pyfsdb

from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter, FileType

def parse_args():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter,
                            description=__doc__,
	                        epilog="Exmaple Usage: pkl-compare [file1, ...]")

    parser.add_argument("-c", "--comparison-records", type=str, nargs="+",
                        default=[],
                        help="Comparison records to use")

    parser.add_argument("-d", "--dump-pkls", action="store_true",
                        help="Just output a pprinted version of the pkl files")

    parser.add_argument("-f", "--fsdb", default=None, type=FileType('w'),
                        help="Write the results as a keyed table")

    parser.add_argument("input_file", nargs="+",
                        help="Input pkl files to read from, or a directory of *.pkl files")

    args = parser.parse_args()

    if not args.dump_pkls and len(args.comparison_records) == 0:
        raise ValueError("At least one comparison record type must be passed to -c")
    return args

def main():
    args = parse_args()

    # read in the results into a file
    results = []
    for infile in args.input_file:
        if os.path.isfile(infile):
            results.append(pickle.load(open(infile, "rb")))
        elif os.path.isdir(infile):
            for dirfile in os.listdir(infile):
                if dirfile[-4:] == '.pkl':
                    joined = os.path.join(infile, dirfile)
                    results.append(pickle.load(open(joined, "rb")))
                else:
                    print(f'ignoring {dirfile}')

    # just print them?
    if args.dump_pkls:
        pprint.pprint(results)
        sys.exit()

    # process the request comparisons into chunks
    comparisons = [x.split('.') for x in args.comparison_records]
    
    # store a nested tree structure of results for counting in N dimensions
    table_results={}
    for record in results:
        values=[]
        for comparison in comparisons:

            # collect the value from the nested structure
            value = record
            for item in comparison:
                if isinstance(value, list):
                    value = value[int(item)]
                else:
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

    if args.fsdb:
        fh = pyfsdb.Fsdb(out_file_handle=args.fsdb)
        column_names = []
        for comparison in comparisons:
            # just record the final struct name
            # (XXX: this won't work in a parallel tree with identical names)
            column_names.append(comparison[-1])
        column_names.append('count')

        fh.column_names = column_names

        for resultkey in table_results:
            save_results(fh, table_results[resultkey], [resultkey])

    else:
        # just print the results
        pprint.pprint(table_results)


def save_results(fh, struct, resultkeys):
    """Recursively descend and save the tree"""
    if 'ans' in struct:
        fh.append([*resultkeys, struct['ans']])
    else:
        for key in struct:
            save_results(fh, struct[key], [*resultkeys, key])

if __name__ == "__main__":
    main()