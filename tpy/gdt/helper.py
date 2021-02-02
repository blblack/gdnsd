"""Helper functions keep actual tests more DRY / declarative."""
import copy

import dns
import dns.query
from dns.rdatatype import *
from dns.rdataclass import *


def _section_parse(sec_array):
    return list(map(lambda x: dns.rrset.from_text(*x), sec_array))


def assert_response(dmn, qname, qtype=A, qflags='', flags='QR AA',
                    rcode='NOERROR', answer=[], auth=[], addtl=[],
                    stats=['udp_reqs', 'noerror']):
    """Assert that qname+qtype produce a given response and stats."""
    __tracebackhide__ = True
    question = dns.message.make_query(qname, qtype)
    question.flags = dns.flags.from_text(qflags)
    expected = dns.message.make_response(question)
    expected.flags = dns.flags.from_text(flags)
    expected.set_rcode(dns.rcode.from_text(rcode))
    expected.answer = _section_parse(answer)
    expected.authority = _section_parse(auth)
    expected.additional = _section_parse(addtl)
    base_stats = dmn.get_stats()
    expected_stats = copy.deepcopy(base_stats)
    for name in stats:
        expected_stats[name] += 1
    resp = dns.query.udp(
        question, '127.0.0.1', timeout=1, port=dmn.port, ignore_unexpected=True
    )
    if resp != expected:
        print("*** Expected Response:\n%s\n" % (expected))
        print("*** Actual Response:\n%s\n" % (resp))
        assert 0
    # XXX we probably need to repeatedly poll here until we see the updates or
    # timeout, like we did before, or else there's a race here that can fail
    # for no good reason, sometimes on some platforms.
    post_stats = dmn.get_stats()
    if expected_stats != post_stats:
        print("*** Stats Mismatch:")
        for k in expected_stats.keys():
            if expected_stats[k] != post_stats[k]:
                print("  %s - wanted: %s got: %s" % (
                    k,
                    expected_stats[k] - base_stats[k],
                    post_stats[k] - base_stats[k]
                ))
        assert 0


def get_zone_keys(dmn, keyring, zone):
    """Fetches zone-level DNSKEY for later validation"""
    __tracebackhide__ = True
    zname = dns.name.from_text(zone)
    question = dns.message.make_query(zname, DNSKEY, use_edns=True,
                                      payload=1232, want_dnssec=True)
    resp = dns.query.udp(
        question, '127.0.0.1', timeout=1, port=dmn.port, ignore_unexpected=True
    )
    try:
        dnskey = resp.find_rrset(dns.message.ANSWER, zname, IN, DNSKEY)
        rrsig = resp.find_rrset(dns.message.ANSWER, zname, IN, RRSIG, DNSKEY)
        keyring[zname] = dnskey
        dns.dnssec.validate(dnskey, rrsig, keyring)
    except KeyError:
        raise Exception("No signed DNSKEY in response from zone %s" % (zone))
    except dns.dnssec.ValidationFailure:
        raise Exception("Zone %s DNSKEY self-sign does not validate" % (zone))
