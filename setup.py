import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gawseed-threat-feed-tools",
    version="1.1.11",
    author="Wes Hardaker and USC/ISI",
    author_email="opensource@hardakers.net",
    description="Tools to search network data logs for threat feed data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gawseed/threat-feed-tools",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'threat-search = gawseed.threatfeed.tools.main:main',
            'pkl-to-report = gawseed.threatfeed.tools.pkl2report:main',
            'pkl-compare = gawseed.threatfeed.tools.pklcompare:main',
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    install_requires=['pyfsdb>=0.9.92',
                      'kafka-python',
                      'python-dateutil',
                      'jinja2',
                      'pyyaml>5',
                      'msgpack',
                      'lz4',
                      'graphviz',
                      'dnssplitter',
                      'urllib3'],
    python_requires = '>=3.0',
    test_suite='nose.collector',
    tests_require=['nose'],
)
