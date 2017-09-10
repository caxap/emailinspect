# -*- coding: utf-8 -*-

from __future__ import unicode_literals


import re
from email import utils


__all__ = ['split_email', 'UserCheck', 'DomainCheck', 'is_non_str_iterable',
           'to_iterable']


def is_non_str_iterable(value):
    return not isinstance(value, (basestring, str)) and hasattr(value, '__iter__')


def to_iterable(value):
    return value if is_non_str_iterable(value) else [value]


def split_email(email):
    if not email:
        return '', ''

    _, email = utils.parseaddr(email.strip().lower())
    user, _, domain = email.partition('@')
    return user, domain.rstrip('.')


class Checker(object):

    @classmethod
    def from_file(cls, filename, **kwargs):
        with open(filename, 'r') as f:
            return cls([l.strip() for l in f.readlines()], **kwargs)

    def __init__(self, patterns, escape=True, chunk_size=20):
        self.patterns = patterns
        self.escape = escape
        self.chunk_size = chunk_size
        self._compiled_patterns = None

    def prepare_value(self, value):
        return value

    def prepare_pattern(self, pttrn):
        if self.escape:
            pttrn = re.escape(pttrn)
        if not pttrn.startswith('^'):
            pttrn = '^' + pttrn
        if not pttrn.endswith('$'):
            pttrn += '$'
        return pttrn

    def compile_patterns(self):
        res, l, n = [], self.patterns, self.chunk_size
        chunks = [l[i:i + n] for i in range(0, len(l), n)]
        for chunk in chunks:
            chunk = [self.prepare_pattern(pttrn) for pttrn in chunk]
            pttrn = '(' + ')|('.join(chunk) + ')'
            res.append(re.compile(pttrn, re.I))
        return res

    def check(self, *args):
        if not args:
            raise ValueError("At least one value to chech is required.")

        if not self._compiled_patterns:
            self._compiled_patterns = self.compile_patterns()

        for value in args:
            value = self.prepare_value(value)
            for pttrn in self._compiled_patterns:
                if pttrn.search(value):
                    return True
        return False

    def __call__(self, *args, **kwargs):
        return self.check(*args, **kwargs)


class UserCheck(Checker):

    def prepare_value(self, email):
        return split_email(email)[0]


class DomainCheck(Checker):

    def prepare_value(self, email):
        user, domain = split_email(email)
        return domain or user
