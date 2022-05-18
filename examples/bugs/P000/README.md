This python prototype of pyparsing
properly handles

multiple Views and its multiple Zones.

Also ensures ordered dictionary (by virtue of Python 3.7+)

Now, I just need to deploy these changes 
throughout the bind9\_parser

NOTE:  'views' is mandatory in order to ensure the
proper ordering of 'view' record, given that they
may have differing `match-clients`, `allow-query`,
and `allow-query-on`.

Fixes: [Issue 7](https://github.com/egberts/bind9_parser/issues)
