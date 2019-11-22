#!/usr/bin/env python3
"""
File: isc_acl.py

Clause: acl

List: GeoIP

Title: Elements Provided for Access Control List

Description: Provides ACL-related grammar in PyParsing engine
             for ISC-configuration style, mostly GeoIP.

             This is rarely use as it requires BIND_GEOIP compiler
             define to be defined.

"""
from pyparsing import CaselessKeyword, Word, alphanums, nums, alphas,\
    Optional, Combine, CaselessLiteral
from bind9_parser.isc_utils import fqdn_name, semicolon


# All GeoIP fields are quotable, using either single-quote or double-quote
# TODO Add single/double quote support for GeoIP
acl_geoip_ISO_3166_1_alpha_2 = Word(alphas, exact=2)  # US
acl_geoip_ISO_3166_alpha_3 = Word(alphas, exact=3)  # USA
acl_geoip_ISO_3166_numeric = Word(nums, exact=3)  # US=840

acl_geoip_db_field_value = Word(alphanums, exact=64)

acl_geoip_country_type = Word(alphanums + '-\'', max=64)('country_type')
acl_geoip_region_type = Word(alphanums + '-\'', max=64)('region')
acl_geoip_city_type = Word(alphanums + '-\'', max=64)('city')
acl_geoip_continent_type = Word(alphanums, max=64)('continent')
acl_geoip_postal_type = Word(alphanums + '--/', max=64)('postal')
acl_geoip_metro_type = Word(alphanums + '-\'', max=64)('metro')
acl_geoip_area_type = Word(alphanums + '-\'', max=64)('area')
acl_geoip_tz_type = Word(alphanums + '-/', max=64)('tz')

acl_geoip_isp_type = Word(
    alphanums
    + '-/.,=&!@#$%^&*()_+-=[]{}\\<>?', max=64
)('isp')

acl_geoip_org_type = Word(
    alphanums
    + '-/.,=&!@#$%^&*()_+-=[]{}\\<>?', max=64
)('org')

acl_geoip_asnum_type = Combine(
    CaselessLiteral('A')
    + CaselessLiteral('S')
    + Word(nums, max=6)
)

acl_geoip_domain_type = fqdn_name('domain')
acl_geoip_netspeed_type = Word(alphanums + '-+><=,', max=64)('netspeed')

acl_geoip_db_element = (
    CaselessKeyword('db')
    + acl_geoip_db_field_value
    # No semicolon here!
)

acl_geoip_country_element = (
        CaselessKeyword('country').suppress()
        + (
                acl_geoip_country_type
                ^ acl_geoip_ISO_3166_alpha_3
                ^ acl_geoip_ISO_3166_1_alpha_2
        )
)('country')

acl_geoip_region_element = (
    CaselessKeyword('region').suppress()
    + acl_geoip_region_type
)('region')

acl_geoip_city_element = (
    CaselessKeyword('city').suppress()
    + acl_geoip_city_type
)

acl_geoip_continent_element = (
    CaselessKeyword('continent').suppress()
    + acl_geoip_continent_type
)

acl_geoip_postal_element = (
    CaselessKeyword('postal').suppress()
    + acl_geoip_postal_type
)

acl_geoip_metro_element = (
    CaselessKeyword('metro').suppress()
    + acl_geoip_metro_type
)

acl_geoip_area_element = (
    CaselessKeyword('area').suppress()
    + acl_geoip_area_type
)

acl_geoip_tz_element = (
    CaselessKeyword('tz').suppress()
    + acl_geoip_tz_type
)

acl_geoip_isp_element = (
    CaselessKeyword('isp').suppress()
    + acl_geoip_isp_type
)

acl_geoip_org_element = (
    CaselessKeyword('org').suppress()
    + acl_geoip_org_type
)

acl_geoip_asnum_element = (
    CaselessKeyword('asnum').suppress()
    + acl_geoip_asnum_type
)

acl_geoip_domain_element = (
    CaselessKeyword('domain').suppress()
    + acl_geoip_domain_type
)

acl_geoip_netspeed_element = (
    CaselessKeyword('netspeed').suppress()
    + acl_geoip_netspeed_type
)

acl_geoip_group = (
    acl_geoip_country_element('country4')
    | acl_geoip_region_element
    | acl_geoip_city_element
    | acl_geoip_continent_element
    | acl_geoip_postal_element
    | acl_geoip_metro_element
    | acl_geoip_area_element
    | acl_geoip_tz_element
    | acl_geoip_isp_element
    | acl_geoip_org_element
    | acl_geoip_asnum_element
    | acl_geoip_domain_element
    | acl_geoip_netspeed_element
)('geoip')

acl_geoip_element = (
        CaselessKeyword('geoip')
        + Optional(acl_geoip_db_element)
        + acl_geoip_group
        + semicolon
)
