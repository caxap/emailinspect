# -*- coding: utf-8 -*-

from .base import (
    is_valid_address, is_free, is_disposable, is_role,
    is_fastmail, is_google, is_yahoo, is_microsoft, normalize,
    guess_emails
)
from .smtp import (
    resolve_mx_records, verify_smtp_connection, verify_smtp_recipients,
    verify_smtp_recipient
)
from .inspect import inspect_list, inspect, EmailAddress


__all__ = ['is_valid_address', 'is_free', 'is_disposable', 'is_role',
           'is_fastmail', 'is_google', 'is_yahoo', 'is_microsoft',
           'normalize', 'guess_emails',
           'resolve_mx_records', 'verify_smtp_connection',
           'verify_smtp_recipients', 'verify_smtp_recipient',
           'inspect_list', 'inspect', 'EmailAddress']

__version__ = '1.0.0'
