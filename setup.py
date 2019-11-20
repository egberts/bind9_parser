#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import findpackages
from setuptools import setup


setup(
    name='bind9-parser',
    version='0.9.7',
    url='https://github.com/egberts/isc-config',
    license='MIT',
    author='Steve Egbert',
    author_email='egberts@yahoo.com',
    description='ISC configuration file parser',
    keywords='bind9 parser isc named.conf',
    platforms='any',
    setup_requires=["pytest-runner"],
    tests_require=["pytest"],
    py_modules=['bind9-parser'],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
    ],
)
