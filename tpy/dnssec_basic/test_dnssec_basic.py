"""Test very basic DNSSEC things to ensure the testsuite itself is working."""
from gdt import helper

# Common SOA record for example.com
zsoa = ['example.com.', 900, 'IN', 'SOA',
        'ns1.example.com. hostmaster.example.com. 1 7200 1800 259200 900']

keyring = {}

def test_get_keys(gdnsd):
    """Fetches DNSSEC keys for use below, and validates their self-sig"""
    helper.get_zone_keys(gdnsd, keyring, 'example.com.')


# The stuff below doesn't do DNSSEC just yet, still figuring that part out!


def test_positive_a(gdnsd):
    """A basic positive A response."""
    helper.assert_response(
        gdnsd, qname='ns1.example.com',
        answer=[['ns1.example.com.', 86400, 'IN', 'A', '192.0.2.42']],
    )


def test_noerror_srv(gdnsd):
    """A basic negative NOERROR response."""
    helper.assert_response(
        gdnsd, qname='ns1.example.com', qtype='SRV',
        auth=[zsoa],
    )


def test_nxd(gdnsd):
    """A basic NXDOMAIN."""
    helper.assert_response(
        gdnsd, qname='ns2.example.com',
        auth=[zsoa], rcode='NXDOMAIN', stats=['udp_reqs', 'nxdomain'],
    )
