#
# THOUGHTS:
# 0) Once things are working, import all the neat features of our main t/Makefile.am (proper cleanup and distribution, AM_V silences, etc)
#   AM_V_GEN can be done with PYTEST_ADDOPTS="-q"
# 1) Has to work without tox/venv for real distro packaging (can't fetch from net, use distro pkg to provide dnspython, etc)
#    autoconf will find python3.6+, dnspython, cryptography, pytest, maybe others?
# 2) Should allow tox for situations where it makes sense (more-manual builds that find this easier), possibly with --test-with-tox flag to configure or something, which changes things up in this Makefile.am to execute a tox venv to run the pytest.
#
#pytest-xdist: this parallelizes by-file as intended, but then our testports all collide...
#PYTEST_ADDOPTS="-n auto --dist=loadscope" SBIN_GDNSD_PATH="$(abs_top_builddir)/src/gdnsd" $(PYTHON) -m pytest

.PHONY: precheck
precheck:
	@if test "x$(HAVE_TSUITE_PYTHON)" == x0; then \
		echo "Cannot 'make check' or 'make installcheck' without required Python modules (see 'configure' output)"; \
		exit 101; \
	fi

check-local: precheck
	SBIN_GDNSD_PATH="$(abs_top_builddir)/src/gdnsd" $(PYTHON) -m pytest

installcheck-local: precheck
	SBIN_GDNSD_PATH="$(sbindir)/gdnsd" $(PYTHON) -m pytest
