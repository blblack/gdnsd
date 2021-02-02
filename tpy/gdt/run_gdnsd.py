"""Holds the RunGdnsd class and associated helper functions."""

# --- known missing bits:
# valgrind TEST_RUNNER support
# state tracking accept filters for special TCP tests:
#    $ACCF_DNS_FAIL = 1 if m{Failed to install 'dnsready' SO_ACCEPTFILTER};
#    $ACCF_DATA_FAIL = 1 if m{Failed to install 'dataready' SO_ACCEPTFILTER};
# --- we could perhaps  get rid of control socket pathname len limitations by
# adding an undocumented option to gdnsd and gdnsdctl to use a pre-set FD#
# created by socketpair() in the test setup, which then doesn't require any
# run_dir, etc... and then move the basepath out of /tmp/ .  Can this work for
# replace-testing too, at least when the daemon spawns its own replacement?
# Not sure how you'd keep the outer gdnsdctl hooked up, though...

import json
import os
import shutil
import socket
import struct
import subprocess
import time
from string import Template


def _recurse_copy_tmpl(in_dir, out_dir, subs):
    __tracebackhide__ = True
    os.makedirs(out_dir, exist_ok=True)
    for dent in os.listdir(in_dir):
        in_path = os.path.join(in_dir, dent)
        out_path = os.path.join(out_dir, dent)
        if os.path.isdir(in_path):
            _recurse_copy_tmpl(in_path, out_path, subs)
        elif out_path.endswith('.tmpl'):
            with open(in_path, 'r') as infile:
                with open(out_path[:-5], 'w') as outfile:
                    outfile.write(Template(infile.read()).substitute(subs))
        else:
            shutil.copy(in_path, out_path)


class RunGdnsd:
    """Encapsulates launch and cleanup of a gdnsd instance for testing."""

    def _launch_and_wait_ready(self):
        with open(self.log_path, 'w') as logfile:
            self.proc = subprocess.Popen(
                [self.gdnsd_bin, '-Dc', self.etc_dir, 'start'],
                stdout=logfile.fileno(),
                stderr=subprocess.STDOUT
            )
        retries = 100  # more for TEST_RUNNER?
        ok = False
        while not ok and retries > 0:
            retries -= 1
            time.sleep(0.1)  # longer for TEST_RUNNER?
            if self.proc.poll() is not None:
                raise Exception("gdnsd died early!")
            try:
                with open(self.log_path, 'r') as logfile:
                    for logline in logfile:
                        if 'DNS listeners started' in logline:
                            ok = True
            except IOError:
                pass
        if not ok:
            raise Exception("gdnsd failed to become ready on time!")

    def _setup_csock(self):
        self.csock = socket.socket(socket.AF_UNIX,
                                   socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.csock.settimeout(10)
        self.csock.connect(str(self.csock_path))
        self.csock.sendall(b'I\x00\x00\x00\x00\x00\x00\x00')
        reply = self.csock.recv(8)
        if len(reply) != 8:
            raise Exception("Bad response to control socket INFO request")

    def __init__(self, gdnsd_bin, base_dir, copy_etc_from):
        """Launch gdnsd, confirm liveness, and connect controlsock."""
        __tracebackhide__ = True
        self.port = 12345  # XXX later, need multiple for parallelism
        self.csock = None
        self.proc = None

        # set up paths
        for p in ('etc/zones', 'var/lib/gdnsd', 'run'):
            base_dir.joinpath(p).mkdir(parents=True, exist_ok=True)
        self.gdnsd_bin = gdnsd_bin
        self.base_dir = base_dir
        self.etc_dir = base_dir.joinpath('etc')
        self.run_dir = base_dir.joinpath('run')
        self.state_dir = base_dir.joinpath('var/lib/gdnsd')
        self.csock_path = self.run_dir.joinpath('control.sock')
        self.log_path = base_dir.joinpath('gdnsd.out')

        # copy and template etc/ config/zones stuff
        tmpl_subs = {
            "run_dir": self.run_dir,
            "state_dir": self.state_dir,
            "dns_port": self.port,
        }
        _recurse_copy_tmpl(copy_etc_from, self.etc_dir, tmpl_subs)

        self._launch_and_wait_ready()
        self._setup_csock()

    def get_stats(self):
        """Fetch gdnsd current stats from controlsock."""
        assert self.proc and self.csock
        self.csock.sendall(b'S\x00\x00\x00\x00\x00\x00\x00')
        hdr = self.csock.recv(8)
        if len(hdr) != 8 or chr(hdr[0]) != 'A':
            raise Exception("Stats fetch failed (header)")
        dlen = struct.unpack('II', hdr)[1]
        data = b''
        while len(data) < dlen:
            new_data = self.csock.recv(dlen - len(data))
            if len(new_data) == 0:
                raise Exception("Stats fetch failed (EOF)")
            data += new_data
        raw = json.loads(data)
        stats = raw['stats']
        udp = dict(map(lambda kv: ("udp_" + kv[0], kv[1]), raw['udp'].items()))
        tcp = dict(map(lambda kv: ("tcp_" + kv[0], kv[1]), raw['tcp'].items()))
        return {**stats, **udp, **tcp}

    def __del__(self):
        """Universal idempotent destructor which stops the daemon.

        This destructor is meant to handle __init__ failures and also to be
        idempotent so that we can call it explicitly to ensure daemons are torn
        down in a timely fashion and don't stack up due to GC laziness.
        """
        __tracebackhide__ = True
        if self.csock is not None:
            self.csock.close()
            self.csock = None
        proc = self.proc
        if not proc:
            return
        self.proc = None
        rc = proc.poll()
        if rc is not None:
            if rc != 0:
                raise Exception("gdnsd exited with status %s" % (rc))
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        raise Exception("gdnsd failed to stop without resorting to SIGKILL!")
