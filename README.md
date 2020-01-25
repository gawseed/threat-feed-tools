# Overview

The gawseed-threat-feed-tools package provides a mechanism that binds
together:

- A threat feed source that returns a list of "threats"
- A data source, that returns rows of data to search through for the threats
- A searcher that can bind the two together, looking for threats/data
  that meet particular criteria 
- A list of "enrichers" that can take the results of any matches and
  gather additional context to pass to the ....
- A report generator that can take the results of everything and
  print/save the results

# Usage

Typical usage would be running `threat-feed.py` and loading a YAML
configuration file (passed to the `-y` switch) to bind the above
modules together.  See `theat-feed.py --config-templates` for a
selection of YAML configuration templates to use when creating config
files.

# Example configuration

Coming soon...
