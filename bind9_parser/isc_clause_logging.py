#!/usr/bin/env python3
"""
File: isc_clause_logging.py

Clause: logging

Title: Clause statement for logging

Description: Provides logging channels-related grammar in
             PyParsing engine for ISC-configuration style

"""

from pyparsing import Word, Group, Optional, Keyword, Literal, \
    srange, OneOrMore, ZeroOrMore, ungroup
from bind9_parser.isc_utils import semicolon, number_type, \
    isc_boolean, lbrack, rbrack, \
    name_type, quoted_path_name, size_spec

logging_chan_name = Word(srange('[a-zA-Z0-9]') + '_-', max=63)
logging_chan_name.setName('<channel_name>')
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
        - size_spec('size_spec')
)

logging_chan_file_path_element = (
    Keyword('file').suppress()
    - quoted_path_name('path_name')('path_name')
    - Optional(logging_chan_file_path_version_element)
    - Optional(logging_chan_file_path_size_element)
)

logging_chan_syslog_facility_name = (
        Literal('kern')
        | Literal('user')
        | Literal('mail')
        | Literal('daemon')
        | Literal('auth')
        | Literal('syslog')
        | Literal('lpr')
        | Literal('news')
        | Literal('uucp')
        | Literal('cron')
        | Literal('authpriv')
        | Literal('ftp')
        | Literal('local0')
        | Literal('local1')
        | Literal('local2')
        | Literal('local3')
        | Literal('local4')
        | Literal('local5')
        | Literal('local6')
        | Literal('local7')
)('facility')
logging_chan_syslog_facility_name.setName('<syslog_facility>')

logging_chan_syslog_element = (
        Keyword('syslog').suppress()
        - logging_chan_syslog_facility_name
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
        + semicolon
)

logging_chan_syslog_severity_select = (
        Literal('critical')
        | Literal('error')
        | Literal('warning')
        | Literal('notice')
        | Literal('info')
        | Literal('dynamic')
        | (
                Literal('debug').suppress()
                - Optional(number_type(''))('')
        )('debug')
)('')
logging_chan_syslog_severity_select.setName('critical|error|warning|notice|info|debug <level>|dynamic')

logging_chan_syslog_severity_element = (
        Group(
            Keyword('severity').suppress()
            - logging_chan_syslog_severity_select
        )('severity')
        + semicolon
)('')

logging_chan_print_category_element = (
    (
        Keyword('print-category').suppress()
        - isc_boolean('print_category')
    )
    + semicolon
)

logging_chan_print_severity_element = (
        Keyword('print-severity').suppress()
        - isc_boolean('print_severity')
        + semicolon
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
        + semicolon
)

#  [ buffered <boolean>; ]
logging_chan_buffered_element = (
    Keyword('buffered').suppress()
    - isc_boolean('buffered')
    + semicolon
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
        logging_chan_name('channel_name')
        + lbrack
        - logging_chan_method_element
        + rbrack
    )
    + semicolon
)('channel')

logging_channel_name_series = (
    OneOrMore(
        logging_chan_name
        + semicolon
    )
)('logging_channel_name_series')
logging_channel_name_series.setName('<channel_name>; [...]')

# Too many ISC Bind9 categories to put here, must be future-proof.
logging_category_name = name_type
logging_category_name.setName('<category_name>')

logging_stmt_category_set = (
    Keyword('category').suppress()
    + Group(
        logging_category_name('category_group_name')
        + lbrack
        - logging_channel_name_series('categories')
        + rbrack
    )
    + semicolon
)('category_group')

logging_stmt_set = (
    logging_stmt_channel_set
    | logging_stmt_category_set
)

logging_stmt_series = (
    OneOrMore(
        Group(
            logging_stmt_set
        )
    )
)

clause_stmt_logging_standalone = (
    Keyword('logging').suppress()
    - Group(
        lbrack
        + logging_stmt_series
        + rbrack
    )('logging')
    + semicolon
)


# There is no clause_stmt_logging_series because 'logging' clause may only occur ONCE per configuration file
