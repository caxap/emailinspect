# -*- coding: utf-8 -*-

from __future__ import unicode_literals


import re
from os.path import join, dirname
from .utils import split_email, UserCheck, DomainCheck


__all__ = ['is_valid_address', 'is_free', 'is_disposable', 'is_role',
           'is_fastmail', 'is_google', 'is_yahoo', 'is_microsoft',
           'normalize', 'VALID_ADDRESS_REGEXP']


ROOT = dirname(__file__)


# All we are really doing is comparing the input string to one
# gigantic regular expression.  But building that regexp, and
# ensuring its correctness, is made much easier by assembling it
# from the "tokens" defined by the RFC.  Each of these tokens is
# tested in the accompanying unit test file.
#
# The section of RFC 2822 from which each pattern component is
# derived is given in an accompanying comment.
#
# (To make things simple, every string below is given as 'raw',
# even when it's not strictly necessary.  This way we don't forget
# when it is necessary.)
#
WSP = r'[\s]'                                        # see 2.2.2. Structured Header Field Bodies
CRLF = r'(?:\r\n)'                                   # see 2.2.3. Long Header Fields
NO_WS_CTL = r'\x01-\x08\x0b\x0c\x0f-\x1f\x7f'        # see 3.2.1. Primitive Tokens
QUOTED_PAIR = r'(?:\\.)'                             # see 3.2.2. Quoted characters
FWS = r'(?:(?:' + WSP + r'*' + CRLF + r')?' + \
      WSP + r'+)'
CTEXT = r'[' + NO_WS_CTL + \
        r'\x21-\x27\x2a-\x5b\x5d-\x7e]'              # see 3.2.3
CCONTENT = r'(?:' + CTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.3 (NB: The RFC includes COMMENT here
# as well, but that would be circular.)
COMMENT = r'\((?:' + FWS + r'?' + CCONTENT + \
          r')*' + FWS + r'?\)'                       # see 3.2.3
CFWS = r'(?:' + FWS + r'?' + COMMENT + ')*(?:' + \
       FWS + '?' + COMMENT + '|' + FWS + ')'         # see 3.2.3
ATEXT = r'[\w!#$%&\'\*\+\-/=\?\^`\{\|\}~]'           # see 3.2.4. Atom
ATOM = CFWS + r'?' + ATEXT + r'+' + CFWS + r'?'      # see 3.2.4
DOT_ATOM_TEXT = ATEXT + r'+(?:\.' + ATEXT + r'+)*'   # see 3.2.4
DOT_ATOM = CFWS + r'?' + DOT_ATOM_TEXT + CFWS + r'?' # see 3.2.4
QTEXT = r'[' + NO_WS_CTL + \
        r'\x21\x23-\x5b\x5d-\x7e]'                   # see 3.2.5. Quoted strings
QCONTENT = r'(?:' + QTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.2.5
QUOTED_STRING = CFWS + r'?' + r'"(?:' + FWS + \
                r'?' + QCONTENT + r')*' + FWS + \
                r'?' + r'"' + CFWS + r'?'
LOCAL_PART = r'(?:' + DOT_ATOM + r'|' + \
                QUOTED_STRING + r')'                    # see 3.4.1. Addr-spec specification
DTEXT = r'[' + NO_WS_CTL + r'\x21-\x5a\x5e-\x7e]'    # see 3.4.1
DCONTENT = r'(?:' + DTEXT + r'|' + \
           QUOTED_PAIR + r')'                        # see 3.4.1
DOMAIN_LITERAL = CFWS + r'?' + r'\[' + \
                 r'(?:' + FWS + r'?' + DCONTENT + \
                 r')*' + FWS + r'?\]' + CFWS + r'?'  # see 3.4.1
DOMAIN = r'(?:' + DOT_ATOM + r'|' + \
         DOMAIN_LITERAL + r')'                       # see 3.4.1
ADDR_SPEC = LOCAL_PART + r'@' + DOMAIN               # see 3.4.1

# A valid address will match exactly the 3.4.1 addr-spec.
VALID_ADDRESS_REGEXP = re.compile('^' + ADDR_SPEC + '$')


def is_valid_address(email_address):
    if email_address:
        return VALID_ADDRESS_REGEXP.match(email_address) is not None
    return False


# Email domain-related checks
is_free = DomainCheck.from_file(join(ROOT, 'free.txt'))
is_disposable = DomainCheck.from_file(join(ROOT, 'disposable.txt'))

# Email user-related checks
is_role = UserCheck.from_file(join(ROOT, 'role.txt'))

# Exchange-related checks
is_fastmail = DomainCheck([
    r'^(.*\.)?fastmail\.com$',
    r'^(.*\.)?messagingengine\.com$',
    r'^(.*\.)?fastmail\.fm$',
], escape=False)

is_google = DomainCheck([
    '^(.*\.)?google\.com$',
    '^(.*\.)?googlemail\.com$',
    '^(.*\.)?gmail\.com$',
], escape=False)

is_microsoft = DomainCheck([
    '^(.*\.)?hotmail\.com$',
    '^(.*\.)?outlook\.com$',
    '^(.*\.)?live\.com$'
], escape=False)

is_yahoo = DomainCheck([
    '^(.*\.)?yahoodns\.net$',
    '^(.*\.)?yahoo\.com$',
    '^(.*\.)?ymail\.com$'
], escape=False)


def normalize(email_address, exchanges=None):
    user, domain = split_email(email_address)

    if not exchanges:
        exchanges = []
    exchanges = [domain] + exchanges

    # Plus addressing is supported by Microsoft domains and FastMail
    if is_microsoft(*exchanges):
        user = user.split('+')[0]

    # GMail supports plus addressing and throw-away period delimiters
    elif is_google(*exchanges):
        user = user.replace('.', '').split('+')[0]

    # Yahoo domain handling of - is like plus addressing
    elif is_yahoo(*exchanges):
        user = user.split('-')[0]

    # FastMail has domain part username aliasing and plus addressing
    # https://www.fastmail.com/help/receive/addressing.html
    elif is_fastmail(*exchanges):
        domain_parts = domain.split('.')
        if len(domain_parts) > 2:
            user, domain = (domain_parts[0], '.'.join(domain_parts[1:]))
        else:
            user = user.split('+')[0]

    return '@'.join([user, domain])


DEFAULT_EMAIL_TEMPLATES = [
    '{first}@{domain}',              # first@domain.com
    '{last}@{domain}',               # last@domain.com
    '{first}{last}@{domain}',        # firstlast@domain.com
    '{first}.{last}@{domain}',       # first.last@domain.com
    '{last}{first}@{domain}',        # lastfirst@domain.com
    '{last}.{first}@{domain}',       # last.first@domain.com

    '{first:.1}{last}@{domain}',     # flast@domain.com
    '{first:.1}.{last}@{domain}',    # f.last@domain.com
    '{first:.1}_{last}@{domain}',    # f_last@domain.com
    '{first}{last:.1}@{domain}',     # firstl@domain.com
    '{first}.{last:.1}@{domain}',    # first.l@domain.com
    '{first}_{last:.1}@{domain}',    # first_l@domain.com

    '{last}{first:.1}@{domain}',     # lastf@domain.com
    '{last}.{first:.1}@{domain}',    # last.f@domain.com
    '{last}_{first:.1}@{domain}',    # last_f@domain.com

    '{first}_{last}@{domain}',       # first_last@domain.com
    '{last}_{first}@{domain}',       # last_first@domain.com
    '{first:.1}{last:.1}@{domain}',  # fl@domain.com
    '{last:.1}{first:.1}@{domain}',  # lf@domain.com
    '{last:.1}{first}@{domain}',     # lfirst@domain.com
    '{last:.1}.{first}@{domain}',    # l.first@domain.com
    '{last:.1}_{first}@{domain}',    # l_first@domain.com
    '{first:.1}@{domain}',           # f@domain.com
]


def guess_emails(domain, data, templates=DEFAULT_EMAIL_TEMPLATES):
    data = dict(data)
    data['domain'] = domain

    possible_emails = []
    for tmpl in templates:
        try:
            possible_emails.append(tmpl.format(**data).lower())
        except KeyError:
            pass
    return possible_emails
