#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Setup script for the bind9_parser module distribution."""

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import io

# The text of the README file
README_name = __file__.replace('setup.py', 'README.md')
with io.open(README_name, encoding='utf8') as README:
    bind9_parser_main_doc = README.read()

packages = [
    'bind9_parser',
]

bind9_parser_version = '0.9.8'

setup(  # Distribution meta-data
    name='bind9_parser',
    version=bind9_parser_version,
    description='Bind9 configuration file parsing module',
    long_description=bind9_parser_main_doc,
    long_description_content_type='text/markdown',
    author='Steve Egbert',
    author_email='egberts@yahoo.com',
    keywords='bind9 configuration parser isc named.conf',
    url='https://github.com/egberts/bind9_parser/',
    download_url='https://github.com/egberts/bind9_parser/archive/0.9.8.tar.gz',
    license='MIT License',
    packages=packages,
    python_requires='>=3.5',
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    install_requires=['pyparsing'],
    platforms='any',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
    ],
)
