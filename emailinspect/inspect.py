# -*- coding: utf-8 -*-

import uuid
from itertools import izip, groupby
from .base import is_valid_address, is_free, is_disposable, is_role, normalize
from .smtp import (
    resolve_mx_records, verify_smtp_recipients, verify_smtp_recipient
)
from .utils import split_email


__all__ = ['inspect_list', 'inspect', 'EmailAddress']


def inspect_list(email_addresses, **smtp_opts):
    """Inspect list of email addresses.

    Arguments:
        email_addresses (Iterable): List of email addresses to check.
        mail_from (str): The optional email address that will be used as
            value for "FROM" smtp setting.
        timeout (int): The optional timeout parameter specifies a timeout in
            seconds for blocking operations like the connection attempt (if
            not specified, the global default timeout setting will be used)
        local_hostname (str): If specified, local_hostname is used as the
            FQDN of the local host in the HELO/EHLO command
        debuglevel (int): Set the debug output level. By default debug mode
            is disabled.
    """
    # TODO: check length of `email_addresses` list according RFC
    # TODO: use a global cache for MX requests.
    # TODO: deal with duplicates

    valid_opts = {'mail_from', 'timeout', 'local_hostname', 'debuglevel'}
    extra_opts = set(smtp_opts.keys()) - valid_opts
    if extra_opts:
        raise ValueError(
            "Invalid argument(s): {}".format(', '.join(extra_opts)))

    mx_cache = {}
    addresses = [EmailAddress(query) for query in email_addresses]

    for addr in addresses:

        # Validate email format
        addr.valid = is_valid_address(addr.query)
        if not addr.valid:
            addr.status = EmailAddress.UNDELIVERABLE
            addr.reason = 'invalid_email'
            continue

        _, domain = split_email(addr.query)

        # Resolve MX records
        exchanges = mx_cache.get(domain)
        if exchanges is None:
            exchanges = resolve_mx_records(domain)
            mx_cache[domain] = exchanges
        addr.all_exchanges = exchanges

        # Normalize emails according the MX domain
        exchanges = [ex.exchange for ex in addr.all_exchanges]
        addr.email = normalize(addr.query, exchanges=exchanges)

        # Check for free/disposable/role email formats
        addr.user, addr.domain = split_email(addr.email)
        addr.free = is_free(addr.domain)
        addr.disposable = is_disposable(*[addr.domain] + exchanges)
        addr.role = is_role(addr.user)

        if not addr.all_exchanges:
            addr.status = EmailAddress.UNDELIVERABLE
            addr.reason = 'invalid_domain'
        else:
            addr.reason = 'no_connect'

    # Validate SMTP recipients
    with_exchanges = [addr for addr in addresses if addr.all_exchanges]

    for domain, group in groupby(with_exchanges, key=lambda a: a.domain):
        group = list(group)
        first = group[0]  # as all emails in group has the same exchanges
        emails = [addr.email for addr in group]

        opts = dict(smtp_opts)
        # TODO: if `from_email` is invalid, some SMTP servers will reject `FROM` request.
        # opts.setdefault('mail_from', first.email)

        # Use random email to check for catch-all policy
        catch_all_email = '{}@{}'.format(uuid.uuid4(), domain)

        # Iterate exchanges by priority to find working one
        for exchange, _ in first.all_exchanges:
            _, catch_all, reason = verify_smtp_recipient(
                exchange, catch_all_email, **opts)
            if reason == 'no_connect':
                continue

            if catch_all:
                for addr in group:
                    addr.reason = reason
                    addr.catch_all = catch_all
                    addr.exchange = exchange
            else:
                # If there is no catch-all policy, validate recipients for
                # this exchange.
                it = verify_smtp_recipients(exchange, emails, **opts)
                for addr, (_, _, reason) in izip(group, it):
                    addr.reason = reason
                    addr.catch_all = catch_all
                    addr.exchange = exchange
            break

    for addr in with_exchanges:
        if addr.reason == 'accepted_email':
            if addr.disposable or addr.gibberish or addr.catch_all:
                addr.status = EmailAddress.RISKY
            else:
                addr.status = EmailAddress.DELIVERABLE
        else:
            addr.status = EmailAddress.UNDELIVERABLE

    return addresses


def inspect(email_address, **kwargs):
    """ Inspect a email address.

    Arguments:
        (same as for `inspect_list` function)
    """
    return inspect_list([email_address], **kwargs)[0]


class EmailAddress(object):
    DELIVERABLE, UNDELIVERABLE, RISKY, UNKNOWN = \
        ('deliverable', 'undeliverable', 'risky', 'unknown')

    def __init__(self, query):
        self.query = query
        self.valid = None
        self.email = None
        self.user = None
        self.domain = None
        self.free = None
        self.disposable = None
        self.role = None
        self.gibberish = False  # Not supported yet
        self.catch_all = False
        self.exchange = None
        self.all_exchanges = None
        self.status = self.UNKNOWN
        self.reason = None

    @property
    def is_deliverable(self):
        return self.status == self.DELIVERABLE

    @property
    def is_risky(self):
        return self.status == self.RISKY

    @property
    def is_undeliverable(self):
        return self.status == self.UNDELIVERABLE

    def __str__(self):
        return self.email or self.query

    def __repr__(self):
        return '{} - {} ({})'.format(self.email or self.query,
                                     self.status, self.reason)
