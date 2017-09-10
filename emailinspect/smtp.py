# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import socket
import smtplib
from collections import namedtuple

try:
    import dns
    import dns.exception
    import dns.resolver
    import dns.rdatatype
except ImportError:
    dns = None  # noqa


__all__ = ['resolve_mx_records', 'verify_smtp_connection',
           'verify_smtp_recipients', 'verify_smtp_recipient']


DEFAULT_LOCAL_HOSTNAME = 'google-public-dns-a.google.com'  # socket.getfqdn('8.8.8.8')
DEFAULT_TIMEOUT = 20
DEFAULT_EMAIL_FROM = 'hello@google.com'


class Exchange(namedtuple('Exchange', 'exchange preference')):

    def __str__(self):
        return self.exchange

    __repr__ = __str__


def resolve_mx_records(qname, **kwargs):
    if not dns:
        raise Exception('To check the mx records or to check if the '
                        'email address exists you must have installed '
                        'the `dnspython` python package')

    qname = qname[qname.find('@') + 1:]  # check for email address
    raise_exception = kwargs.pop('raise_exception', False)
    kwargs['rdtype'] = dns.rdatatype.MX

    try:
        answer = dns.resolver.query(qname, **kwargs)
        exchanges = [
            Exchange(mx.exchange.to_text().rstrip('.'), mx.preference)
            for mx in answer
        ]
        exchanges.sort(key=lambda ex: ex.preference)
        return exchanges
    except dns.exception.DNSException:
        if raise_exception:
            raise
    return []


class SMTPSessionError(Exception):

    def __init__(self, reason, smtp_opts=None):
        self.reason = reason
        self.smtp_opts = smtp_opts
        super(SMTPSessionError, self).__init__(reason)

    def __str__(self):
        return self.reason


class SMTPSession(object):

    def __init__(self, host, mail_from=DEFAULT_EMAIL_FROM,
                 local_hostname=DEFAULT_LOCAL_HOSTNAME,
                 timeout=DEFAULT_TIMEOUT,
                 debuglevel=0):
        self.host = host
        self.mail_from = mail_from
        self.local_hostname = local_hostname
        self.timeout = timeout
        self.debuglevel = debuglevel
        self._smtp = None

    def quit(self):
        try:
            if self._smtp:
                self._smtp.quit()
        except smtplib.SMTPServerDisconnected:
            pass
        self._smtp = None

    def start(self):
        self._smtp = smtplib.SMTP(local_hostname=self.local_hostname,
                                  timeout=self.timeout)
        smtp = self._smtp
        smtp.set_debuglevel(self.debuglevel)
        try:
            try:
                code, _ = smtp.connect(self.host)
                if code != 220:
                    self.quit()
                    # Mail server exists but respond w/ an error
                    raise SMTPSessionError('invalid_smtp')
            except socket.error:
                # Failed to connect
                raise SMTPSessionError('no_connect')

            try:
                smtp.ehlo_or_helo_if_needed()
            except smtplib.SMTPHeloError:
                self.quit()
                # Failed to process greeting
                raise SMTPSessionError('invalid_smtp')

            code, _ = smtp.mail(self.mail_from)
            if code != 250:
                self.quit()
                # Sender was refused
                raise SMTPSessionError('invalid_smtp')

            return smtp

        except socket.timeout:
            raise SMTPSessionError('timeout')

        except smtplib.SMTPServerDisconnected:
            raise SMTPSessionError('invalid_smtp')

    def restart(self):
        self.quit()
        self.start()

    def recipients(self, *email_addresses):
        assert email_addresses, "at least one email address should be given"
        assert self._smtp, "run start() first"

        active_session = True
        for email_addr in email_addresses:
            try:
                if active_session:
                    code, _ = self._smtp.rcpt(email_addr)
                    accepted = code in [250, 251]
                    yield email_addr, accepted

                    # Try to reconnect on specific server errors
                    if code in [552, 554]:
                        self.restart()
                else:
                    yield email_addr, False
            except (socket.timeout, smtplib.SMTPServerDisconnected):
                # Server may unexpectedly close connection (spam filter?)
                active_session = False
                self.quit()

    def __enter__(self):
        if not self._smtp:
            self.start()
        return self

    def __exit__(self, *exc_details):
        self.quit()


def verify_smtp_connection(host, **smtp_opts):
    try:
        with SMTPSession(host, **smtp_opts):
            return (True, 'valid_smtp')
    except SMTPSessionError as e:
        return (False, e.reason)


def verify_smtp_recipients(host, email_addresses, **smtp_opts):
    if isinstance(email_addresses, (str, bytes, unicode)):
        email_addresses = [email_addresses]

    try:
        with SMTPSession(host, **smtp_opts) as s:
            for email_addr, accepted in s.recipients(*email_addresses):
                reason = 'accepted_email' if accepted else 'rejected_email'
                yield email_addr, accepted, reason
    except SMTPSessionError as e:
        for email_addr in email_addresses:
            yield email_addr, False, e.reason


# Just simple shortcut for one email address
def verify_smtp_recipient(host, email_address, **smtp_opts):
    return verify_smtp_recipients(host, [email_address], **smtp_opts).next()
