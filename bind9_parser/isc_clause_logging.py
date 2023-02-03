#!/usr/bin/env python3
"""
File: isc_clause_logging.py

Clause: logging

Title: Clause statement for logging

Description: Provides logging channels-related grammar in
             PyParsing engine for ISC-configuration style
             
    
logging {
        category <string> { <string>; ... }; // may occur multiple times
        channel <string> {
                buffered <boolean>;
                file <quoted_string> [ versions ( unlimited | <integer> ) ]
                    [ size <size> ] [ suffix ( increment | timestamp ) ];
                null;
                print-category <boolean>;
                print-severity <boolean>;
                print-time ( iso8601 | iso8601-utc | local | <boolean> );
                severity <log_severity>;
                stderr;
                syslog [ <syslog_facility> ];
        }; // may occur multiple times
};


"""
import copy

from pyparsing import Word, Group, Optional, Keyword, Literal, \
    srange, OneOrMore, ZeroOrMore, Char, ungroup, Combine
from bind9_parser.isc_utils import semicolon, number_type, \
    isc_boolean, lbrack, rbrack, \
    name_type, dequoted_path_name, size_spec

logging_chan_name = (
    Word(srange('[a-zA-Z0-9]') + '_-', max=63)
)

logging_chan_name_dequotable = (
    (
            Char('"').suppress() + logging_chan_name + Char('"').suppress()
    )
    ^ (
            Char("'").suppress() + logging_chan_name + Char("'").suppress()
    )
    ^ logging_chan_name
)
logging_chan_name_dequotable.setName('<quotable_chan_name>')

# logging {
#    [ channel <channel_name> {
#        [ buffered <boolean>; ]
#        ( file <path_name>
#            [ version (<number> |unlimited) ]
#            [ size <size_spec> ]
#          | stderr;
#          | null;
#          | syslog <log_facility>;
#        )
#      [ severity ( critical | error | warning | notice
#                   info | debug [ <level> ] | dynamic ); ]
#      [ print-category <boolean>; ]
#      [ print-severity <boolean>; ]
#      [ print-time ( iso8601 | iso8601-utc | local | <boolean>) ;  ]
#    }; ]
#    [ category category_name {
#      channel_name ; [ channel_name ; ... ]
#    }; ]
#    ...
# }

logging_chan_file_path_version_element = (
    Keyword('versions').suppress()
    - (
            Literal('unlimited')
            | number_type('')
    )('versions')
)

logging_chan_file_path_size_element = (
        Literal('size').suppress()
        - size_spec('size_spec')   # do not ungroup this, they have optional 'K', 'M', and 'G' notation to its integer
)

logging_chan_file_path_element = (
    Keyword('file').suppress()
    - dequoted_path_name('path_name').setName('path_name')
    - Optional(logging_chan_file_path_version_element)
    - Optional(logging_chan_file_path_size_element)
)

logging_chan_syslog_facility_name = (
    Keyword('kern')
    ^ Keyword('user')
    ^ Keyword('mail')
    ^ Keyword('daemon')
    ^ Keyword('auth')
    ^ Keyword('syslog')
    ^ Keyword('lpr')
    ^ Keyword('news')
    ^ Keyword('uucp')
    ^ Keyword('cron')
    ^ Keyword('authpriv')
    ^ Keyword('ftp')
    ^ Keyword('local0')
    ^ Keyword('local1')
    ^ Keyword('local2')
    ^ Keyword('local3')
    ^ Keyword('local4')
    ^ Keyword('local5')
    ^ Keyword('local6')
    ^ Keyword('local7')
)('facility')
logging_chan_syslog_facility_name.setName(
    '(kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|local1-7)')

logging_chan_syslog_element = (
    Group(
        (
            Keyword('syslog').suppress()
            + logging_chan_syslog_facility_name
        )
        ^ (
            Keyword('syslog').suppress()
        )
    )('syslog')
)

logging_chan_stderr_keyword = (
    Keyword('stderr')
)('io')
logging_chan_null_keyword = (
    Keyword('null')
)('io')

logging_chan_file_method = (
    (
        logging_chan_file_path_element
        ^ logging_chan_syslog_element
        ^ logging_chan_stderr_keyword
        ^ logging_chan_null_keyword
    )
    - semicolon
)

logging_chan_syslog_severity_select = (
    (
        (
            Keyword('critical')
            ^ Keyword('error')
            ^ Keyword('warning')
            ^ Keyword('notice')
            ^ Keyword('info')
            ^ Keyword('dynamic')
            ^ (
                Group(
                    Keyword('debug').suppress()
                    - (
                        number_type('debug_level')
                    )
                )
            )('debug')
            ^ Keyword('debug')('debug')
        )
    )
)
logging_chan_syslog_severity_select.setName('critical|error|warning|notice|info|debug <level>|dynamic')

logging_chan_syslog_severity_element = (
    Group(
        Keyword('severity').suppress()
        - logging_chan_syslog_severity_select
    )('severity')
    - semicolon
)('')

logging_chan_print_category_element = (
    (
        Keyword('print-category').suppress()
        - isc_boolean('print_category')
    )
    - semicolon
)

logging_chan_print_severity_element = (
    Keyword('print-severity').suppress()
    - isc_boolean('print_severity')
    - semicolon
)

#  [ print-time ( iso8601 | iso8601-utc | local | <boolean>) ;  ]
logging_chan_print_time_element = (
    Keyword('print-time').suppress()
    - (
            Keyword('iso8601-utc')
            | Keyword('iso8601')
            | Keyword('local')
            | isc_boolean
    )('print_time')
    - semicolon
)

#  [ buffered <boolean>; ]
logging_chan_buffered_element = (
    Keyword('buffered').suppress()
    - isc_boolean('buffered')
    - semicolon
)

logging_chan_method_option_set = (
    logging_chan_syslog_severity_element
    | logging_chan_print_time_element
    | logging_chan_print_category_element
    | logging_chan_print_severity_element
    | logging_chan_buffered_element
)

logging_chan_method_option_series = (
    ZeroOrMore(logging_chan_method_option_set)
)

logging_chan_method_element = (
    logging_chan_file_method
    - logging_chan_method_option_series
)

logging_stmt_channel_set = (
    Keyword('channel').suppress()
    - Group(
        ungroup(logging_chan_name_dequotable)('channel_name')
        - lbrack
        - logging_chan_method_element
        - rbrack
    )('channels*')
    - semicolon
)

logging_channel_name_series = (
    OneOrMore(
        logging_chan_name_dequotable
        - semicolon
    )
)('channel_names')
logging_channel_name_series.setName('<dequotable_channel_name>; [...]')

# Too many ISC Bind9 categories to put here, must be future-proof.
logging_category_name = copy.deepcopy(name_type)

logging_category_name_dequotable = (
    (
            Combine(Char('"').suppress() + logging_category_name + Char('"').suppress())
    )
    ^ (
            Combine(Char("'").suppress() + logging_category_name + Char("'").suppress())
    )
    ^ logging_category_name
)
logging_chan_name_dequotable.setName('<dequotable-chan-name>')

#
# CATEGORIES
#
logging_stmt_category_set = (
    Keyword('category').suppress()
    + Group(
        (
            ungroup(logging_category_name_dequotable)('category_group_name')
            - lbrack
            - logging_channel_name_series
            - rbrack
        )
    )('category_groups*')
    - semicolon
)

logging_stmt_set = (
    logging_stmt_channel_set
    ^ logging_stmt_category_set
)

logging_stmt_series = (
    Group(
        OneOrMore(
            logging_stmt_set
        )
    )('logging')
)

clause_stmt_logging_standalone = (
    Keyword('logging').suppress()
    - (   # no Group() here, at most one 'logging' clause allowed.
        lbrack
        - logging_stmt_series
        - rbrack
    )  # no '*' here, at most one 'logging clause allowed.
    - semicolon
)


# There is no clause_stmt_logging_series because 'logging' clause may only occur ONCE per configuration file
