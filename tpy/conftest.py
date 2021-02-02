"""Testsuite-global pytest fixtures go here."""
import os

import pytest

from gdt.run_gdnsd import RunGdnsd


@pytest.fixture(scope="module")
def gdnsd(tmp_path_factory, request):
    """Launch a managed gdnsd instance as a pytest fixture."""
    gdnsd_bin = os.path.normpath(os.getenv('SBIN_GDNSD_PATH'))
    outdir = tmp_path_factory.mktemp(os.path.basename(request.fspath))
    copy_etc_from = os.path.join(os.path.dirname(request.fspath), 'etc')
    running = RunGdnsd(gdnsd_bin, outdir, copy_etc_from)
    yield running
    running.__del__()  # avoid daemon pileup if GC is lazy
