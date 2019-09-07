#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (C) 2014-2019 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
#
# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, see
# <https://www.gnu.org/licenses/>.

'''
This script is useful for checking the differences between
an old LC_CTYPE file /usr/share/i18n/locale/i18n and a
new one generated by gen_unicode_ctype.py

To see how it is used, call it with the “-h” option:

    $ ./ctype_compatibility.py -h
    … prints usage message …
'''

import sys
import re
import unicodedata
import argparse

from ctype_compatibility_test_cases import TEST_CASES

def get_lines_from_file(filename):
    '''Get all non-comment lines from a i18n file

    Also merge all lines which are continued on the next line because
    they end in “/” into a single line.
    '''
    with open(filename) as i18n_file:
        current_line = ''
        for line in i18n_file:
            line = line.strip('\n')
            if '%' in line:
                if line.endswith('/'):
                    line = line[0:line.find('%')] + '/'
                else:
                    line = line[0:line.find('%')]
            line = line.strip()
            if line.endswith('/'):
                current_line += line[:-1]
            else:
                yield current_line + line
                current_line = ''
    if current_line: # file ends with a continuation line
        yield current_line

def extract_character_classes(filename):
    '''Get all Unicode code points for each character class from a file

    Store these code points in a dictionary using the character classes
    as keys and the list of code points in this character class as values.

    In case  of the character classes “toupper”, “tolower”, and “totitle”,
    these area actually pairs of code points
    '''
    ctype_dict = {}
    for line in get_lines_from_file(filename):
        for char_class in [
                'upper',
                'lower',
                'alpha',
                'digit',
                'outdigit',
                'space',
                'cntrl',
                'punct',
                'graph',
                'print',
                'xdigit',
                'blank',
                'combining',
                'combining_level3',
                'toupper',
                'tolower',
                'totitle']:
            match = re.match(r'^('
                             +'(?:(?:class|map)\s+")'
                             +re.escape(char_class)+
                             '(?:";)\s+'
                             +'|'
                             +re.escape(char_class)+'\s+'
                             +')', line)
            if match:
                if char_class not in ctype_dict:
                    ctype_dict[char_class] = []
                process_chars(
                    ctype_dict[char_class],
                    line[match.end():])
    return ctype_dict

def process_chars(char_class_list, code_point_line):
    '''
    Extract Unicode values from code_point_line
    and add to the list of code points in a character class
    '''
    for code_points in code_point_line.split(';'):
        code_points = code_points.strip()
        match = re.match(r'^<U(?P<codepoint>[0-9A-F]{4,8})>$', code_points)
        if match: # <Uxxxx>
            char_class_list.append(
                int(match.group('codepoint'), 16))
            continue
        match = re.match(
            r'^<U(?P<codepoint1>[0-9A-F]{4,8})>'
            +'\.\.'+
            '<U(?P<codepoint2>[0-9A-F]{4,8})>$',
            code_points)
        if match: # <Uxxxx>..<Uxxxx>
            for codepoint in range(
                    int(match.group('codepoint1'), 16),
                    int(match.group('codepoint2'), 16) + 1):
                char_class_list.append(codepoint)
            continue
        match = re.match(
            r'^<U(?P<codepoint1>[0-9A-F]{4,8})>'
            +'\.\.\(2\)\.\.'+
            '<U(?P<codepoint2>[0-9A-F]{4,8})>$',
            code_points)
        if match: # <Uxxxx>..(2)..<Uxxxx>
            for codepoint in range(
                    int(match.group('codepoint1'), 16),
                    int(match.group('codepoint2'), 16) + 1,
                    2):
                char_class_list.append(codepoint)
            continue
        match = re.match(
            r'^\('
            +'<U(?P<codepoint1>[0-9A-F]{4,8})>'
            +','+
            '<U(?P<codepoint2>[0-9A-F]{4,8})>'
            +'\)$',
            code_points)
        if match: # (<Uxxxx>,<Uxxxx>)
            char_class_list.append((
                int(match.group('codepoint1'), 16),
                int(match.group('codepoint2'), 16)))
            continue
        sys.stderr.write(
            ('None of the regexps matched '
             + 'code_points=%(cp)s in code_point_line=%(cpl)s\n') %{
            'cp': code_points,
            'cpl': code_point_line
        })
        exit(1)

def compare_lists(old_ctype_dict, new_ctype_dict):
    '''Compare character classes in the old and the new LC_CTYPE'''
    print('****************************************************')
    print('Character classes which are only in the new '
          + 'or only in the old file:')
    for char_class in sorted(old_ctype_dict):
        if char_class not in new_ctype_dict:
            print('Character class %s is in old ctype but not in new ctype'
                  %char_class)
    for char_class in sorted(new_ctype_dict):
        if char_class not in old_ctype_dict:
            print('Character class %s is in new ctype but not in old ctype'
                  %char_class)
    for char_class in sorted(old_ctype_dict):
        print("****************************************************")
        print("%s: %d chars in old ctype and %d chars in new ctype" %(
            char_class,
            len(old_ctype_dict[char_class]),
            len(new_ctype_dict[char_class])))
        print("----------------------------------------------------")
        report(char_class,
               old_ctype_dict[char_class],
               new_ctype_dict[char_class])

def report_code_points(char_class, code_point_list, text=''):
    '''Report all code points which have been added to or removed from a
    character class.
    '''
    for code_point in sorted(code_point_list):
        if type(code_point) == type(int()):
            print('%(char_class)s: %(text)s: %(char)s %(code_point)s %(name)s'
                  %{'text': text,
                    'char': chr(code_point),
                    'char_class': char_class,
                    'code_point': hex(code_point),
                    'name': unicodedata.name(chr(code_point), 'name unknown')})
        else:
            print(('%(char_class)s: %(text)s: '
                   + '%(char0)s → %(char1)s '
                   + '%(code_point0)s → %(code_point1)s '
                   + '%(name0)s → %(name1)s') %{
                'text': text,
                'char_class': char_class,
                'char0': chr(code_point[0]),
                'code_point0': hex(code_point[0]),
                'name0': unicodedata.name(chr(code_point[0]), 'name unknown'),
                'char1': chr(code_point[1]),
                'code_point1': hex(code_point[1]),
                'name1': unicodedata.name(chr(code_point[1]), 'name unknown')
            })

def report(char_class, old_list, new_list):
    '''Report the differences for a certain LC_CTYPE character class
    between the old and the newly generated state
    '''
    missing_chars = list(set(old_list)-set(new_list))
    print(('%(char_class)s: Missing %(number)d characters '
           + 'of old ctype in new ctype ')
          %{'char_class': char_class, 'number': len(missing_chars)})
    if ARGS.show_missing_characters:
        report_code_points(char_class, missing_chars, 'Missing')
    added_chars = list(set(new_list)-set(old_list))
    print(('%(char_class)s: Added %(number)d characters '
           + 'in new ctype which were not in old ctype')
          %{'char_class': char_class, 'number': len(added_chars)})
    if ARGS.show_added_characters:
        report_code_points(char_class, added_chars, 'Added')


def cperror(error_message, errorcounter=0):
    '''Increase number of errors by one and print an error message'''
    print(error_message)
    return errorcounter + 1

def cpcheck(ctype_dict, code_point_list_with_ranges, char_classes, reason='',
            errorcounter=0):
    '''The parameter “code_point_list_with_ranges” is a list of
    integers or pairs of integers, for example:

    [0x0E31, (0x0E34, 0x0E3A), (0x0E47, 0x0E4E)]

    where the pairs of integers stand for all the code points in the range
    of the two integers given, including the two integers of the pair.

    '''
    for code_point_range in code_point_list_with_ranges:
        for code_point in ([code_point_range]
                           if type(code_point_range) == type(int())
                           else range(code_point_range[0],
                                      code_point_range[1]+1)):
            for char_class_tuple in char_classes:
                char_class = char_class_tuple[0]
                in_char_class = char_class_tuple[1]
                if (code_point in ctype_dict[char_class]) != in_char_class:
                    errorcounter = cperror(
                        ('error: %(code_point)s %(char)s '
                         + '%(char_class)s %(in)s: %(reason)s') %{
                             'code_point': hex(code_point),
                             'char': chr(code_point),
                             'char_class': char_class,
                             'in': not in_char_class,
                             'reason': reason},
                        errorcounter)
    return errorcounter

def tests(ctype_dict, errorcounter = 0):
    '''Test a LC_CTYPE character class dictionary for known errors'''
    # copy the information from ctype_dict (which contains lists) in
    # a new dictionary ctype_dict2 (which contains dictionaries).
    # The checks below are easier with that type of data structure.

    ctype_dict2 = {}
    for key in ctype_dict:
        ctype_dict2[key] = {}
        if ctype_dict[key]:
            if type(ctype_dict[key][0]) == type(int()):
                for value in ctype_dict[key]:
                    ctype_dict2[key][value] = 1
            else: # key is 'toupper', 'tolower', or 'totitle'
                for value in ctype_dict[key]:
                    ctype_dict2[key][value[0]] = value[1]

    for test_case in TEST_CASES:
        errorcounter = cpcheck(ctype_dict2,
                               test_case[0],
                               test_case[1],
                               test_case[2],
                               errorcounter = errorcounter)

    for code_point in range(0, 0x110000):
        # toupper restriction: "Only characters specified for the keywords
	# lower and upper shall be specified.
        if (code_point in ctype_dict2['toupper']
            and code_point != ctype_dict2['toupper'][code_point]
            and not (code_point in ctype_dict2['lower']
                     or code_point in ctype_dict2['upper'])):
            errorcounter = cperror(
                ('error: %(char1)s is not upper|lower '
                 + 'but toupper(%(cp1)s)=%(cp2)s (%(char2)s)') %{
                     'char1': chr(code_point),
                     'cp1': hex(code_point),
                     'cp2': hex(ctype_dict2['toupper'][code_point]),
                     'char2': chr(ctype_dict2['toupper'][code_point])
                 },
                errorcounter)
        # tolower restriction: "Only characters specified for the keywords
	# lower and upper shall be specified.
        if (code_point in ctype_dict2['tolower']
            and code_point != ctype_dict2['tolower'][code_point]
            and not (code_point in ctype_dict2['lower']
                     or code_point in ctype_dict2['upper'])):
            errorcounter = cperror(
                ('error: %(char1)s is not upper|lower '
                 + 'but tolower(%(cp1)s)=%(cp2)s (%(char2)s)') %{
                     'char1': chr(code_point),
                     'cp1': hex(code_point),
                     'cp2': hex(ctype_dict2['tolower'][code_point]),
                     'char2': chr(ctype_dict2['tolower'][code_point])
                 },
                errorcounter)
        # alpha restriction: "Characters classified as either upper or lower
	# shall automatically belong to this class.
        if ((code_point in ctype_dict2['lower']
             or code_point in ctype_dict2['upper'])
            and code_point not in ctype_dict2['alpha']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is upper|lower but not alpha' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        # alpha restriction: "No character specified for the keywords cntrl,
	# digit, punct or space shall be specified."
        if (code_point in ctype_dict2['alpha']
            and code_point in ctype_dict2['cntrl']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is alpha and cntrl' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['alpha']
            and code_point in ctype_dict2['digit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is alpha and digit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['alpha']
            and code_point in ctype_dict2['punct']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is alpha and punct' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['alpha']
            and code_point in ctype_dict2['space']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is alpha and space' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        # space restriction: "No character specified for the keywords upper,
	# lower, alpha, digit, graph or xdigit shall be specified."
	# upper, lower, alpha already checked above.
        if (code_point in ctype_dict2['space']
            and code_point in ctype_dict2['digit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is space and digit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['space']
            and code_point in ctype_dict2['graph']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is space and graph' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['space']
            and code_point in ctype_dict2['xdigit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is space and xdigit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        # cntrl restriction: "No character specified for the keywords upper,
	# lower, alpha, digit, punct, graph, print or xdigit shall be
	# specified."  upper, lower, alpha already checked above.
        if (code_point in ctype_dict2['cntrl']
            and code_point in ctype_dict2['digit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is cntrl and digit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['cntrl']
            and code_point in ctype_dict2['punct']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is cntrl and punct' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['cntrl']
            and code_point in ctype_dict2['graph']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is cntrl and graph' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['cntrl']
            and code_point in ctype_dict2['print']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is cntrl and print' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['cntrl']
            and code_point in ctype_dict2['xdigit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is cntrl and xdigit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        # punct restriction: "No character specified for the keywords upper,
	# lower, alpha, digit, cntrl, xdigit or as the <space> character shall
	# be specified."  upper, lower, alpha, cntrl already checked above.
        if (code_point in ctype_dict2['punct']
            and code_point in ctype_dict2['digit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is punct and digit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['punct']
            and code_point in ctype_dict2['xdigit']):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is punct and xdigit' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point in ctype_dict2['punct']
            and code_point == 0x0020):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is punct.' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        # graph restriction: "No character specified for the keyword cntrl
	# shall be specified."  Already checked above.

        # print restriction: "No character specified for the keyword cntrl
	# shall be specified."  Already checked above.

        # graph - print relation: differ only in the <space> character.
	# How is this possible if there are more than one space character?!
	# I think susv2/xbd/locale.html should speak of "space characters",
	# not "space character".
        if (code_point in ctype_dict2['print']
            and not (code_point in ctype_dict2['graph']
                     or code_point in ctype_dict2['space'])):
            errorcounter = cperror(
                'error: %(char)s %(cp)s is print but not graph|space' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
        if (code_point not in ctype_dict2['print']
            and (code_point in ctype_dict2['graph']
                 or code_point ==  0x0020)):
            errorcounter = cperror(
                'error: %(char)s %(cp)s graph|space but not print' %{
                    'char': chr(code_point),
                    'cp': hex(code_point)
                },
                errorcounter)
    return errorcounter

if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        description='''
        Compare the contents of LC_CTYPE in two files and check for errors.
        ''')
    PARSER.add_argument(
        '-o', '--old_ctype_file',
        nargs='?',
        type=str,
        default='i18n',
        help='The old ctype file, default: %(default)s')
    PARSER.add_argument(
        '-n', '--new_ctype_file',
        nargs='?',
        type=str,
        default='unicode-ctype',
        help='The new ctype file, default: %(default)s')
    PARSER.add_argument(
        '-a', '--show_added_characters',
        action='store_true',
        help=('Show characters which were added to each '
              + 'character class in detail.'))
    PARSER.add_argument(
        '-m', '--show_missing_characters',
        action='store_true',
        help=('Show characters which were removed from each '
              + 'character class in detail.'))
    ARGS = PARSER.parse_args()

    OLD_CTYPE_DICT = extract_character_classes(
        ARGS.old_ctype_file)
    NEW_CTYPE_DICT = extract_character_classes(
        ARGS.new_ctype_file)
    compare_lists(OLD_CTYPE_DICT, NEW_CTYPE_DICT)
    print('============================================================')
    print('Checking for errors in old ctype file: %s' %ARGS.old_ctype_file)
    print('------------------------------------------------------------')
    NUMBER_OF_ERRORS_IN_OLD_FILE = tests(OLD_CTYPE_DICT, errorcounter = 0)
    print('------------------------------------------------------------')
    print('Old file = %s' %ARGS.old_ctype_file)
    print('Number of errors in old file = %s' %NUMBER_OF_ERRORS_IN_OLD_FILE)
    print('------------------------------------------------------------')
    print('============================================================')
    print('Checking for errors in new ctype file: %s' %ARGS.new_ctype_file)
    print('------------------------------------------------------------')
    NUMBER_OF_ERRORS_IN_NEW_FILE = tests(NEW_CTYPE_DICT, errorcounter = 0)
    print('------------------------------------------------------------')
    print('New file = %s' %ARGS.new_ctype_file)
    print('Number of errors in new file = %s' %NUMBER_OF_ERRORS_IN_NEW_FILE)
    print('------------------------------------------------------------')
    if NUMBER_OF_ERRORS_IN_NEW_FILE > 0:
        exit(1)
    else:
        exit(0)
