"""Test very basic things to ensure the testsuite itself is working."""
from gdt import helper

# Common SOA record for example.com
zsoa = ['example.com.', 900, 'IN', 'SOA',
        'ns1.example.com. hostmaster.example.com. 1 7200 1800 259200 900']


def test_positive_a(gdnsd):
    """A basic positive A response."""
    helper.assert_response(
        gdnsd,
        qname='ns1.example.com',
        answer=[['ns1.example.com.', 86400, 'IN', 'A', '192.0.2.42']],
    )


def test_noerror_srv(gdnsd):
    """A basic negative NOERROR response."""
    helper.assert_response(
        gdnsd,
        qname='ns1.example.com', qtype='SRV',
        auth=[zsoa],
    )


def test_nxd(gdnsd):
    """A basic NXDOMAIN."""
    helper.assert_response(
        gdnsd,
        rcode='NXDOMAIN',
        qname='ns2.example.com',
        auth=[zsoa], stats=['udp_reqs', 'nxdomain'],
    )
