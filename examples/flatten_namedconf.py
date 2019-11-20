#!/usr/bin/env python3
#
# flatten_namedconf.py
#
# Short pyparsing script to perform #include inclusions similar
# to the C preprocessor
#
# Produces one big long text content after
# incorporating 'include' file(s)' content
#
#
# TODO: Cannot process this valid 'include"abc.conf";' statement
#  (no whitespace between include keyword and quoted isc_file_name)  BUG
import sys
import errno
import os.path
from pathlib import Path
import argparse
import pyparsing as pp
from bind9_parser.isc_clause import clause_statements, parse_me

g_progname = os.path.basename(__file__)
g_root_dir = '.'  # default to current working directory
g_include_depth = 0
g_include_directive = ''
g_semicolon = ';'
g_pe_clause_include = pp.Keyword("include")
g_verbosity = 0
g_output = None


def process_entire_file_content(a_content_data):
    """
    process_entire_file_content takes the initial ISC-styled configuration file
                            and recursively incorporates all the content of
                            any uncommented 'include' clauses and returns in
                            form of a single continuous configuration file.
                            Each uncommented include clause will be
                            annotated by having its content surrounded by
                            additional '#' comments indicating its isc_file_name
                            of the include file along with its depth level
                            count of any nesting include clauses.
    :param a_content_data: the entire content of ISC-styled configuration
                         file (i.e., named.conf)
    :return: the entire content of configuration file after reading in all
             uncommented include clauses and folding in the content of such
             include files.
    """
    global g_include_depth
    global g_include_directive

    # When encountering quoted string, strip the quotes, if any
    quoted_string = pp.quotedString.addParseAction(pp.removeQuotes)

    # lift isc_file_name and create an 'include_file' attribute
    # TODO: Possible inadvert removal of ';' from its isc_file_name?
    g_include_directive = g_pe_clause_include \
        + (
            quoted_string
            | pp.Word(pp.printables, excludeChars=';')
        )("include_filepath") \
        + g_semicolon
    # BIND provides a number of a_comment formats as follows:
    #
    # /* C style a_comment format needs opening and closing markers
    # ** but allows multiple lines or */
    # /* single lines */
    # // C++ style comments single line format no closing required
    # # PERL/SHELL style comments single lines no closing required
    g_include_directive.ignore(pp.cppStyleComment)
    g_include_directive.ignore(pp.pythonStyleComment)

    # attach include processing method as parse action to
    # g_include_directive expression

    # Add a hook (read_include_contents) to do the following:
    #   * the parser to check for 'include' statement,
    #   * open any 'include' statement found, and
    #   * continue reading those 'include' files.
    g_include_directive.addParseAction(read_include_contents)

    # Now perform the parsing action against that large string
    master_config_content = g_include_directive.transformString(a_content_data)

    return master_config_content


def read_include_contents(st, locn, toks):
    """
    This parser hook routine (as noted by (st, locn, toks) arguments)
    will open another file as pointed to by the toks argument

    :param st: the original string being parsed (see note below)
    :param locn: the location of the matching substring
    :param toks: a list of the matched tokens, packaged as a ParseResults object

    :return: Another long string containing content of include file
    """
    global g_include_depth
    # If include file is an absolute path, make it relative to g_root_dir
    if toks.include_filepath[0:1] == '/':
        include_file_ref = g_root_dir + toks.include_filepath
    else:
        # If include file is a relative, then it is relative to g_root_dir
        include_file_ref = g_root_dir + '/' + toks.include_filepath
    if args.v:
        print('Found:', include_file_ref)
    g_include_depth = g_include_depth + 1

    # Add a a_comment line into expanded master include file
    # for later post-error analysis
    # Do not wrap C-style a_comment ourselves of this same line because
    #   original line may too have this "/* ... */"
    # Only way to avoid already-used but inlined C-style a_comment is to
    #   create a separate line
    # TODO: Strip C-style a_comment from line
    # TODO: Better cyclical detection of file include recursion
    include_echo = "#{}# {}\n".format(g_progname, pp.line(locn, st).strip())
    include_begin_echo = "# Begin of {} file.\n# Nested include-file depth: {}".format(
        include_file_ref,
        # pp.line(locn, st).strip(),
        g_include_depth
    )
    include_end_echo = "# Nested include-file depth: {}\n# End of {} file.".format(
        g_include_depth,
        # pp.line(locn, st).strip(),
        include_file_ref
    )

    # Check if file exist, gracefully raise exception
    next_include_file = ''
    try:
        if g_verbosity:
            print('Opening', include_file_ref)
        next_include_file = Path(include_file_ref).read_text()
    except FileNotFoundError as _ric_err:
        print('read_include_contents: err:', _ric_err)
        raise FileNotFoundError
    # guard against recursive includes (doesn't work for reuse of include files)

    result_include_line = include_echo \
                          + include_begin_echo \
                          + '\n' \
                          + g_include_directive.transformString(next_include_file) \
                          + include_end_echo
    g_include_depth = g_include_depth - 1
    return result_include_line


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        'Build python list/dict from ISC Bind configuration file'
    )
    parser.add_argument('-v',
                        choices=[0, 1, 2],
                        type=int,
                        help='increase output g_verbosity')
    parser.add_argument('-r', '--root',
                        help='Set g_root_dir directory path')
    parser.add_argument('-o', '--output',
                        help='Write flatten named.conf to a specified filespec')
    parser.add_argument('config_filepath',
                        default='named.conf',
                        help='File path to named.conf file')
    args = parser.parse_args()

    if args.v:
        print("g_verbosity turned on")
        g_verbosity = g_verbosity + 1

    if args.output:
        g_output_file = args.output
        if args.v:
            print('Output file:', g_output_file)

    if args.config_filepath is None:
        print("Must specify filepath/filespec to the named.conf file.")
        exit(errno.ENOENT)
    named_conf_filepath = args.config_filepath


    # use g_include_directive.transformString to perform includes
    if args.root is not None:
        g_root_dir = args.root
        # Need to check if there are overlaps, in case there is
        # a named.conf in its original but relative ./etc/bind.
        # Useful if a local but many named.conf files are being
        # tested against a baseline set of include files.
#        len = len(g_root_dir)
#        if g_root_dir[0:len] == named_conf_filepath[0:len]:
#            named_conf_filepath = named_conf_filepath[len:]

    # Check if path ends with '/', if so, trim that '/' off.
    if g_root_dir[-1] == '/':
        g_root_dir = g_root_dir[0:-1]

    if g_verbosity:
        print("Current working directory: ", os.getcwd())
        print('named_conf_filepath:', named_conf_filepath)
        print('g_root_dir::', g_root_dir)

    # Extract the basename of the named.conf filepath
    conf_file_basename = os.path.basename(named_conf_filepath)

    # read contents of starting named.conf file
    # named_conf = 'split-horizon-2-bind9-servers/named-public_all.conf'
    toplevel_config = Path(named_conf_filepath).read_text()

    # Perform two-pass on this configuration file
    # 1. Read in all include files, including nested one
    #    a. Ignore cppStyleComment and pythonStyleComment (in case
    #       an include clause got commented out)
    #    b. Add pythonStyleComment of its isc_file_name and its depth
    #       level of include nesting

    # 1. Now to fold in additional configuration content from
    #    all applicable include files
    single_large_file = process_entire_file_content(toplevel_config)

    # print expanded configuration file
    if g_verbosity:
        print('File: ', single_large_file)
        print("About to parse...")
    clause_statements.ignore(pp.cppStyleComment)
    clause_statements.ignore(pp.pythonStyleComment)
    result = parse_me(clause_statements, single_large_file, True)

    if g_verbosity > 1:
        print('result:', result)
        result.pprint()

    sys.exit(1)
