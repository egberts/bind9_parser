#!/usr/bin/env python3

import sys
import pprint
from examples import namedconfglobal
from bad_tests import test_named_conf_public

pp = pprint.PrettyPrinter(indent=4)


class NamedConf(object):
    """

    """

    ncgv = {}
    current = dict()  # Holds the user's latest settings, only uses dict/list/str types, no OrderedDict

    class_dict = dict()  # It's all about the type() checking
    class_list = list()

    def __init__(self, desired_version="9.10.3", debug=0):
        self.debug = debug

        self.ncgv = namedconfglobal.NamedConfGlobal(desired_version, debug)

        # Why is there a default_value argument in NamedConf class constructor?
        # Because, different default values for different BIND9 version
        self.default_value = {
            'options':
                {
                    'version': 'Still a funky DNS, no?',
                    'listen-on': None,
                    'type': 'master',
                    'notify': 'explicit',
                    'test_default_none': None,
                    'test_default': "usable",
                }
        }

    # supports NamedClass.print()
    def __str__(self):
        return str(self.__class__) + ": " + str(self.__dict__)

    # supports NamedClass.print()
    def __repr__(self):
        from pprint import pformat
        return "<" + type(self).__name__ + "> " + pformat(vars(self), indent=4, width=1)

    # Bad attempt at providing class-based pretty print
    def print(self):
        _pp = pprint.PrettyPrinter()
        print("NamedConf.print.current:", self.current)
        _pp.pprint(self.current)

    # support NamedConf['acl'] mechanism
    def __getitem__(self, val):
        if val not in self.current:
            raise KeyError('Unknown key')  # when the key is unknown, you raise a key err
        return self.current[val]

    # dict = {} unordered, named dist
    # list = [] ordered
    # tuple = () ordered
    def validate_clause_dict(self, clause_name, clause_dict, _config=None):
        """
        validate_clause_dict() basically validates the clause-portion of the dictionary
        :param clause_name:
        :param clause_dict:
        :param _config:
        :return:
        """
        #  if no configuration is given, use the one that is stored in this class
        if _config is None:
            _config = self.current

        if type(clause_dict) is not dict:
            print("ERROR1: NamedConf.integrity_check.validate_clause_dict: "
                  "clause '%s', value '%s' of is a %s type, "
                  "should be a dict type" %
                  (clause_name, clause_dict, type(clause_dict)))
            return False
        for this_entry in clause_dict:
            if self.debug > 2:
                print("    integrity_clause_list: this_entry:", this_entry)
            if type(this_entry) is list or type(this_entry) is dict:
                if self.debug > 2:
                    print("    integrity_clause_list: type(this_entry):", str(type(this_entry)))
                for this_item in this_entry:
                    if self.debug > 2:
                        print("        integrity_clause_list[]: this_item:", this_item)
                    this_value = this_entry[this_item]
                    if self.debug > 2:
                        print("        integrity_clause_list[]: this_value:", this_value)
                    # need better subrecord discriminator, for validation
                    #  self.integrity_clause_list(this_item, this_value, _config=_config)
        return True

    # dict = {} unordered, named dist
    # list = [] ordered
    # tuple = () ordered
    def integrity_clause_list(self, subblock_name, user_config_subblock_list):
        """ integrity_clause_list - the first-level (top-block) keywords to integrity_check at
        :param subblock_name:
        :param user_config_subblock_list:
        :return:
        """
        print("type(clause[subblock_name]):", type(self.current[subblock_name]))
        print("type(user_config_subblock_list):", type(user_config_subblock_list))
        print("type(self.class_list:", type(self.class_list))
        #        print("type(a):", type(a))
        if not isinstance(user_config_subblock_list, list):
            print("ERROR2: NamedConf.integrity_check.validate_clause_"
                  "list: clause '%s', value '%s' of is a %s "
                  "type, should be a list type" %
                  (subblock_name, user_config_subblock_list, type(user_config_subblock_list)))
            return False
        print("user_config_subblock_list matches self.class_list")

        # Now go through each clause
        for user_subblock_entry in user_config_subblock_list:
            if self.debug > 2:
                print("    integrity_clause_list: user_subblock_entry:", user_subblock_entry)
            # Check if global keyword dictionary has an entry for this for further checking
            if user_subblock_entry not in namedconfglobal.g_nc_keywords.keys():
                continue

            # There is something about this keyword found in this subblock,
            # go get more details from global keyword dictionary
            if 'topblock' in namedconfglobal.g_nc_keywords[user_subblock_entry] and \
               'required' in namedconfglobal.g_nc_keywords[user_subblock_entry]:

                # if type(user_subblock_entry) is list or type(user_subblock_entry) is dict:
                if self.debug > 2:
                    print("    integrity_clause_list: type(user_subblock_entry):", str(type(user_subblock_entry)))
                for this_item in user_subblock_entry:
                    if self.debug > 2:
                        print("        integrity_clause_list: this_item:", this_item)
                    this_value = user_subblock_entry[this_item]
                    if self.debug > 2:
                        print("        integrity_clause_list: this_value:", this_value)
                    # need better subrecord discriminator, for validation
                    result = self.integrity_clause_list(this_item, this_value)
                    if not result:
                        return False
        return True

    def integrity_subblock(self, clause_keyword, current_block, clause_subblock_value):

        # Is this clause_keyword a subblock or is it leaf node (end of tree)?
        if clause_keyword not in self.ncgv.versioned_keywords_dictionary[current_block]:
            # We cannot check this as a subblock so exit quietly.
            return True

        # Check if subblock level is the right type
        block_type = self.ncgv.versioned_keywords_dictionary[current_block][clause_keyword]
        if type(block_type) != type(clause_subblock_value):
            if self.debug:
                print("integrity_subblock: blocks[] says clause '%s' should be a %s type, not %s type." %
                      (clause_keyword, type(block_type), type(clause_subblock_value)))
            return False

        if clause_keyword not in self.ncgv.versioned_keywords_dictionary:
            if self.debug:
                print("integrity_subblock: clause '%s' keyword not found in version %s keyword dictionary" %
                      (clause_keyword, self.ncgv.get_version()))
            return False

        # list() or dict(), it depends on keyword['multiple_entries'] True/False
        if self.debug > 1:
            print("    integrity_check: type(userdef_topblock_value):", type(clause_subblock_value))
            print("multiple_entries is in g_nc_keywords:",
                  'multiple_entries' in self.ncgv.versioned_keywords_dictionary[clause_keyword].keys())
            print("And multiple_entries flag is: ",
                  self.ncgv.versioned_keywords_dictionary[clause_keyword]['multiple_entries'])

        valid = self.validate_clause_dict(clause_keyword, clause_subblock_value)
        if not valid:
            return False

        # Check if there is something nest-deeper to test at subblock level

        return True

    # dict = {} unordered, named dist
    # list = [] ordered
    # tuple = () ordered
    def integrity_check(self, config=None):

        if config is None:
            config = self.current
        if not isinstance(config, dict):
            if self.debug:
                print("ERROR3: NamedConf.integrity_check: config argument is not a dict type")
            return False

        # Check the tree of the user-supplied configuration against versioned_valid_keywords_tree
        # Traverse user-supplied configuration tree

        # Check if all required config keywords are in user-supplied config[]
        # We start by looking for all topblock-marked keywords
        # Only 'topblock' has this 'required' checking, no other subblock does.
        for this_valid_kw in self.ncgv.versioned_keywords_dictionary:

            # Check that a versioned dictionary keyword is a 'topblock' and a 'required'
            this_valid_kw_dict = self.ncgv.versioned_keywords_dictionary[this_valid_kw]
            if 'topblock' in this_valid_kw_dict and \
                    this_valid_kw_dict['topblock'] and \
                    'required' in this_valid_kw_dict and \
                    this_valid_kw_dict['required']:
                # Check if user supplied that required keyword
                if this_valid_kw not in config.keys():
                    print('ERROR4: NamedConf.integrity_check: required dict key '
                          'name ({}) is not in your dict'.format(this_valid_kw))
                    return False

        kw_frequency = dict()

        # Check if user gave the right amount of top-level keywords,
        # some required exactly one, others requires 1 or more,
        # and still others required zero or more (don't care condition).
        # Iterate over all topblock keywords given in the user-provided config dictionary
        for user_defined_topblock in config.keys():
            if self.debug > 1:
                print("integrity_check: user-defined clause:", user_defined_topblock)
            if user_defined_topblock not in kw_frequency:
                # this is the first time, initialize a counter
                kw_frequency[user_defined_topblock] = 1
            else:
                kw_frequency[user_defined_topblock] += 1
                if not self.ncgv.versioned_keywords_dictionary[user_defined_topblock]['multiple_entries']:
                    print("ERROR5: NamedConf.integrity_check: Can only "
                          "specify '%s' clause exactly once", user_defined_topblock)
                    return False

        # Master scan, collect all info
        found_zone = False
        found_view = False
        if 'zone' in config:
            found_zone = True
        if 'view' in config:
            found_view = True

        # 'zone' is a v8.1 keyword
        zone_supported = self.ncgv.is_current_version_keyword('zone')
        # 'view' is a v9.0.0 keyword
        view_supported = self.ncgv.is_current_version_keyword('view')

        if view_supported and zone_supported:
            # If a master/slave/stub/hint, then enforce a presence of either 'zone' or 'view'
            if not found_zone and not found_view:
                print("ERROR6: NamedConf.integrity_check: Need at least one 'view' or 'zone' keyword.")
                return False
            if found_zone and found_view:
                print('ERROR7: NamedConf.integrity_check: Cannot use both \'zone\'/\'view\' at top-level config')
                print('ERROR: NamedConf.integrity_check: You can use either \'zone\' or \'view')
                print("ERROR: NamedConf.integrity_check: If using 'view', you can use 'zone' underneath 'view'.")
                return False
        elif zone_supported:
            if not found_zone:
                print("ERROR8: NamedConf.integrity_check: Need at least one 'zone' keyword.")
                return False

#            # is the clause keyword name also a subblock?
#            if user_defined_topblock in self.ncgv.versioned_keywords_dictionary:

#                # Do some more subblock validation
#                result = self.integrity_subblock(user_defined_topblock,
#                                                'topblock',
#                                                 config[user_defined_topblock],
#                                                 )
#                if result is not True:
#                    return False
        if self.debug:
            print("NamedConf.integrity_check(): True")
        return True

    def load(self, _named_conf):
        if self.integrity_check(_named_conf):
            self.current = _named_conf

    def retrieve(self):
        return self.current

    def get_acl(self):
        return self.current['acl']

    def add_acl_name(self, acl_name):
        # if this is the first time 'acl' clause is being added...
        if 'acl' not in self.current.keys():
            print("WARNING: add_acl_name: ACL did not exist, error in __init__(self)")
            self.current.update(dict('acl', []))

        # TODO Validate the argument as <class 'str'>, not str
#        if issubclass(type(acl_name_base), str):
#            print("add_acl: '%s' acl name is a %s type; only str type allowed" %
#                  (acl_name_base, type(acl_name_base)))
#            return False

        # # of acl_names = len(self.current['acl']

        # current['acl'] = acl
        # len(current['acl']) = # of acl names
        # current['acl'][acl_name_base] = acl entry dict {}
        # len(current['acl'][acl_name_base]) = # of acl entries

        # check that ACL is initialized as a dict {}
        if not isinstance(self.current['acl'], dict):
        # if type(self.current['acl']) is not dict:
            print("add_acl_name: ", self.current['acl'])
            print("CRITICAL add_acl: is a %s type; supposed to be a dict() type" % type(self.current['acl']))
            return False

        # Find pre-existing ACL name in acl entry list
        this_acl_list = self.current['acl']

        # Check if we already added this same ACL name
        # Iterate by integer, no key available in ACL
        for key_iter in this_acl_list:
            print("    key_iter:", key_iter)
            this_acl_name = None
            this_acl_list_value = None
            if isinstance(key_iter, int):
                this_acl_list_value = this_acl_list[key_iter]
                print("    talv:", this_acl_list_value)
                this_acl_name = this_acl_list_value['acl_label']
            elif isinstance(key_iter, dict):
                last_idx = 0
                for idx in key_iter:
                    last_idx = last_idx
                this_acl_name, this_acl_list_value = this_acl_list[last_idx]
            if this_acl_name == acl_name:
                print("ERROR9: add_acl: '%s' acl name already in ACL list: has '%s'" %
                      (acl_name, this_acl_list_value))
                return False
        if self.debug:
            print("add_acl: '%s' acl name is being freshly added" % acl_name)

        if self.debug > 1:
            print("  add_acl: this_acl_list:", this_acl_list)
            print("  add_acl: type(this_acl_list):", type(this_acl_list))

        if self.debug > 1:
            print('    add_acl: before:', self.current['acl'])
        new_index = len(self.current['acl'])
        new_acl = {'acl_label': acl_name}
        self.current['acl'][new_index] = {}
        self.current['acl'][new_index] = new_acl
        if self.debug > 1:
            print('    add_acl: after:', self.current['acl'])
        return True

    def add_acl_items(self, a_acl_name, a_acl_item, a_not_operator=False):
        """
        acl_name_base/acl_items is 1:*
        :param a_acl_name:
        :param a_acl_item:
        :param a_not_operator:
        :return:
        """
        if type(a_acl_item) is not dict:
            print("ERROR10: add_acl_item: a_acl_item argument '%s' is a %s type; not a dict type" %
                  (a_acl_item, type(a_acl_item)))
            return False
#        acl_dict = self.current['acl']
#        print('add_acl_items: before key:', acl_dict)
#        print("add_acl_items: type(acl_dict):", type(acl_dict))
#        print('    add_acl_items: len(acl_dict:', len(acl_dict))
        # We purposely do not support named key into acl's multiple entries, use integer
        for acl_name_idx in self.current['acl']:
            # print("    add_acl_items: acl_name_id:", acl_name_id)
            this_acl_name_dict = None
            if isinstance(acl_name_idx, int):
                # Retrieve the entire dict for that one ACL declaration (by id)
                this_acl_name_dict = self.current['acl'][acl_name_idx]
                # print("    add_acl_items: this_acl_name_dict", this_acl_name_dict)

                # Pick up the ACL name using 'acl_label' key
                this_acl_items_name = this_acl_name_dict['acl_label']
                # print("    add_acl_items: this_acl_items_name:", this_acl_items_name)
            elif isinstance(acl_name_idx, dict):
                last_index = 0
                for index in self.current['acl']:
                    last_index = index
                this_acl_items_name, this_acl_name_dict = self.current['acl'][last_index]

            # See if this ACL label name already exists in the entire ACL
            if this_acl_items_name == a_acl_name:

                # Update route
                formatted_item = {'acl_label': a_acl_name,
                                  0: {'acl_value': a_acl_item, 'operator': a_not_operator}}
                print("    WARNING: add_acl_items: ACL '%s' name already exist, replacing '%s' with '%s'" %
                      (a_acl_name, this_acl_name_dict, formatted_item))
                self.current['acl'][acl_name_id] = formatted_item
                return True
        # No matching acl_name_base, make new ACL name for this item
        # Insert route
        # Get next index ID
        new_index = len(self.current['acl'])

        # Add ACL name
        self.add_acl_name(a_acl_name)

        # Format ACL item dict
        formatted_item = {'acl_label': a_acl_name,
                          0: {'acl_value': a_acl_item, 'operator_not': a_not_operator}
                          }

        # Insert formatted ACL item dict into new ACL name index
        self.current['acl'][new_index] = formatted_item
        return True

    def get(self):
        return self.current

    def get_default_option(self, k):
        # find default value
        if k not in self.default_value['options']:
            raise KeyError('Unknown options key' + k)  # when the key is unknown, you raise a key err
        return self.default_value['options'][k]

    def get_option(self, k):
        print("get_option(%s): " % k, end='')
        if k not in self.current['options']:
            raise KeyError('Unknown options key' + k)  # when the key is unknown, you raise a key err
        return self.current['options'][k]

    def get_option_or_default(self, k):
        print("get_option(%s): " % k, end='')
        if k not in self.current['options']:
            # attempt to find its default value
            return self.get_default_option(k)
        return self.current['options'][k]

    def print_options_default(self):
        print("options {")
        if 'options' in self.ncgv.versioned_keywords_dictionary:
            for this_option in self.ncgv.versioned_keywords_dictionary['options'].keys():
                print("Scanning 'options { %s..." % this_option)
                if self.ncgv.versioned_keywords_dictionary['options'][this_option] is not None:
                    print("ncgv_options[%s]: %s" %
                          (this_option,
                           self.ncgv.versioned_keywords_dictionary['options'][this_option]))
                    if 'subblock_options' in self.ncgv.versioned_keywords_dictionary['options'][this_option]:
                        if self.ncgv.versioned_keywords_dictionary['options'][this_option]['subblock_options']:
                            print(" "*4,)
                            print("%s %s;" %
                                  (this_option,
                                   self.ncgv.versioned_keywords_dictionary['options'][this_option]))
                        else:
                            print("no default value given")
                    else:
                        print("default not declared")
                else:
                    print("%s option is None" % this_option)
        else:
            print("undefined")
        print("};")

    # this_dict is typically a named dict using name as an indexing mechanism using an integer
    # {
    #   0: { ... },
    #   15: { },
    #   36: { .... },
    # }
    def validate_array(self, this_dict):
        if not isinstance(this_dict, dict):
            print("validate_array: argument is not a dict, I got %s instead", type(this_dict))
            return False

        for this_index in this_dict.keys():
            if type(this_index) is str:
                print("validate_array: '%s' is not a string." % this_index)
            if type(this_index) is int:
                print("validate_array: '%s' is not a integer." % this_index)
            if type(this_index) is dict:
                print("validate_array: '%s' is not a dict." % this_index)
            if type(this_index) is list:
                print("validate_array: '%s' is not a list." % this_index)
            if type(this_index) is tuple:
                print("validate_array: '%s' is not a tuple." % this_index)

    def validate_node(self, keyword, node, indent=0):
        print(" "*indent, end='')
        print("kw: '%s', node: '%s'" % (keyword, node))
        kw_type = type(keyword)
        if kw_type == str:
            print(" "*indent, end='')
            print(" kw '%s' is an str" % keyword)
        elif kw_type == int:
            print(" "*indent, end='')
            print(" kw '%s' is an int" % keyword)
        elif kw_type == list:
            assert "Crapped"
        elif kw_type == dict:
            assert "Crapped2"

        node_type = type(node)
        if node_type == list:  # '[]' don't have named dict, no-pair-key-value here
            print(" "*indent, end='')
            print("kw: '%s', node is a list" % keyword)
            # iterate it further
            for int_index in range(len(node)):
                print(" "*indent, end='')
                print("kw: '%s', node iterating %d" % (keyword, int_index))
                node_value = node[int_index]
                result = self.validate_node(node, node_value, indent+4)
                if not result:
                    return False
        elif node_type == dict:
            print(" "*indent, end='')
            print("kw: '%s', node is a dict" % keyword)
            for name_index in node:
                print(" "*indent, end='')
                print("kw: '%s', node is iterating %s" % (keyword, name_index))
                node_value = node[name_index]
#                if self.ncgv.is_user_defined_indice(keyword):
#                    if type(node_value) == str:
#                        if not self.ncgv.is_current_version_keyword(name_index):
#                            print(" "*(indent), end='')
#                            print("Keyword '%s' is not a current version" % (name_index))
#                            return False
                result = self.validate_node(name_index, node_value, indent+4)
                if not result:
                    return False
        return True

    # Integrity is the structure of the configuration
    # Validity is the correctness of the configuration data
    def validate(self, config=None):
        """
        validate - determines the correctness of the user-supplied
                   configuration and its data (particularly its data)

                   integrity() function only checks its structure.
        :param config:  user-supplied configuration dictionary
        :return: isc_boolean, returns True if all values are within range and correct
                 returns False if at least one data is out-of-range.
        """
        if config is None:
            config = self.current
        if type(config) is not dict:
            return False

        valid = True  # knock-down validity only once.

        # do the first level before letting recursive processing take over
        for keyword in config:
            print("top-level: %s" % keyword)
            if not self.ncgv.is_current_version_keyword(keyword):
                valid = False
                continue
            node = config[keyword]
            if not self.validate_node(keyword, node, indent=4):
                print("FAILED")
                valid = False
        return valid

    def get_views(self, config=None):
        result = list()
        if config is None:
            config = self.current
        if 'view' in config:
            assert(type(config['view']) == list)
            for _kw in config['view']:  # integer indexing
                print("kw:", _kw)
                assert(type(_kw) == dict)
                for kw2 in _kw:
                    print("kw2:", kw2)
                    assert(type(kw2) == str)
                    result.append(kw2)
        return result

    def get_zones(self, config=None):
        result = list()
        if config is None:
            config = self.current
        if 'zone' in config:
            assert(type(config['zone']) == list)
            for _kw in config['zone']:  # integer indexing
                print("_kw:", _kw)
                assert(type(_kw) == dict)
                for kw2 in _kw:
                    print("kw2:", kw2)
                    assert(type(kw2) == str)
                    result.append(kw2)
        if not result:
            # check for zones under 'view'
            if 'view' in config:
                assert(type(config['view']) == list)
                for _kw in config['view']:  # integer indexing
                    print("_kw:", _kw)
                    assert(type(_kw) == dict)
                    for kw2 in _kw:
                        print("kw2:", kw2)
                        assert(type(kw2) == str)
                        if _kw == 'zone':
                            result.append(self.get_zones(config['view'][0][kw2]))
        return result


if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=4, depth=6, width=132)

    nc = NamedConf(desired_version="9.10.3", debug=1)

    # Load the configurationA
    myconf = test_named_conf_public.g_named_conf_split_horizon_internal
    nc.load(myconf)

    print(nc.current)
    #    print(nc.current.view)  # need attrs for that.
    print(nc.current['view'])
    for index in range(len(nc.current['view'])):
        print(nc.current['view'][index])
    print("view[0]:", nc.current['view'][0])
    print("dir(view[0]):", dir(nc.current['view'][0]))
    for kw in nc.current['view'][0]:
        print("kw:", kw)
    print("view[0]['cable']:", nc.current['view'][0]['cable'])
    if 'cable' in nc.current['view'][0]:
        print("that worked")
    print("Zones: ", nc.get_zones(myconf))
    print("Views: ", nc.get_views(myconf))

    print("config initialized")
    print("  nc.get_acl():", nc.get_acl())  # __ class variable
    print("  nc['acl']:", nc['acl'])  # __getitem__
    nc.integrity_check()
    print()
    print("Adding ACL...")
    pp.pprint(nc)
    nc.add_acl_name('my_acl_name')
    nc.integrity_check()
    pp.pprint(nc)
    nc.add_acl_name('all_acls')
    nc.integrity_check()
    nc.add_acl_items('my_acl_name', {'ip': '127.0.0.1', 'not_operator': True})
    nc.integrity_check()
    nc.add_acl_items('my_acl_name', '127.0.1.1')
    nc.integrity_check()
    print("nc.config:", nc.current)
    print("nc['acl']:", nc.current['acl'])
    # print("nc.print():", nc.print())
    print("nc(after):", pp.pprint(nc))

    print("####################################################")
    print("Start from scratch...")
    clause = NamedConf(debug=1)
    clause['acl']['my_alias_name'] = {0: '127.0.0.1'}
    clause['options']['version'] = "Funky DNS, uh?"
    clause['options']['listen_on'] = {
        0: {'ip': '127.0.0.1', 'not_operator': True},
        1: {'ip': '127.0.1.1', 'not_operator': True},
    }
    for a in clause['options']['listen_on']:
        print("    listen_on:", a)
    print("2nd listen:", clause['options']['listen_on'][1])
    clause['view']['red'] = {'type': 'slave'}
    print("red_type:", clause['view']['red']['type'])
    print("clause:", clause)
    print("operator?:", clause['options']['listen_on'][0]['not_operator'])
    print()
    pp.pprint(clause)

    # Find  'no_such' option
    print("no_such:", clause['options'].get('no_such'))
    print("get_option('test_default_none", clause.get_option_or_default('test_default_none'))
    print("get_option('test_default", clause.get_option_or_default('test_default'))

    # Iterate on 'listen_on'
    for listen_on in clause['options']['listen_on']:
        print("Listening on ", clause['options']['listen_on'][listen_on])

    print("get_option('version')", clause.get_option('version'))
    print("get_option_or_default('version')", clause.get_option_or_default('version'))

    # Iterate on 'zone's tuples.
    for zone_dict in clause['zone'].items():
        # gets the { 'red': {...} }
        print("Zone: %s" % (str(zone_dict)))

    for zone_name in clause['zone']:
        print("Zone name: %s" % zone_name)

    # 1st indice - array[0..] of clauses
    pp.pprint(clause)

    sys.exit(0)
