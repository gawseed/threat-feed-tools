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

    parser.add_argument("-V", "--verbose", action="store_true",
                        help="Verbose output")

    parser.add_argument("input_file", nargs="+",
                        help="Input pkl files to read from, or a directory of *.pkl files")

    args = parser.parse_args()

    if not args.dump_pkls and len(args.comparison_records) == 0:
        raise ValueError("At least one comparison record type must be passed to -c")
    return args


def find_results(input_files, verbose=False, starting_results=[]):
    """Read in a (recursive) directory of pkl files and return a list of
    their contents
    """
    results = starting_results

    for infile in input_files:
        if os.path.isfile(infile):
            results.append(pickle.load(open(infile, "rb")))
        elif os.path.isdir(infile):
            for dirfile in os.listdir(infile):
                if dirfile[0] == '.':
                    continue

                path = os.path.join(infile, dirfile)

                if os.path.isdir(path):
                    results.extend(find_results([path]))
                elif dirfile[-4:] == '.pkl':
                    results.append(pickle.load(open(path, "rb")))
                elif verbose:
                    sys.stderr.write(f'ignoring {path}')

    return results


warnings = {}
def warn_once(warning):
    if warning not in warnings:
        warnings[warning] = 1
        sys.stderr.write(warning)


def flatten_results(results, comparison_records, print_warning=True):
    """Flattens and extract a deep structure of results based on a list of
    comparisons desired."""

    # process the request comparisons into chunks
    comparisons = [x.split('.') for x in comparison_records]

    # store a nested tree structure of results for counting in N dimensions
    table_results = {}
    for record in results:
        values = []

        # if a tree doesn't have an item, we skip the counting
        try:
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
        except Exception:
            if print_warning:
                print(f"failed to find {comparisons}")
            pass

    return table_results


def save_results(fh, struct, resultkeys):
    """Recursively descend and save the tree"""
    if 'ans' in struct:
        fh.append([*resultkeys, struct['ans']])
    else:
        for key in struct:
            save_results(fh, struct[key], [*resultkeys, key])


def output_to_fsdb(table_results, comparisons, out_file_handle):
    fh = pyfsdb.Fsdb(out_file_handle=out_file_handle)
    column_names = []
    for comparison in comparisons:
        # just record the final struct name
        # (XXX: this won't work in a parallel tree with identical names)
        column_names.append(comparison[-1])
    column_names.append('count')

    fh.column_names = column_names

    for resultkey in table_results:
        save_results(fh, table_results[resultkey], [resultkey])


def main():
    args = parse_args()

    # read in the results into a file
    results = find_results(args.input_file, args.verbose)

    # just print them?
    if args.dump_pkls:
        pprint.pprint(results)
        sys.exit()

    table_results = flatten_results(results, args.comparison_records)

    if args.fsdb:
        output_to_fsdb(table_results, args.comparison_records, args.fsdb)
    else:
        # just print the results
        pprint.pprint(table_results)


if __name__ == "__main__":
    main()
