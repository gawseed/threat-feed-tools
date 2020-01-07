import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="gawseed-threat-feed-tools",
    version="0.9.0",
    author="Wes Hardaker and USC/ISI",
    author_email="opensource@hardakers.net",
    description="Tools to search network data logs for threat feed data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gawseed/threat-feed-tools",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'threat-search.py = gawseed.threatsearch.main:main',
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires = '>=3.0',
    test_suite='nose.collector',
    tests_require=['nose'],
)