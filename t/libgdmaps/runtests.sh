#!/bin/sh
# Why not do this within build.zig directly?
# Because TEST_CFDIR has to be an env var which points at a generated directory
# full of links and decompressed files, and there's no variant of
# Step.Run.setEnvironmentVariable() that takes a LazyPath, and no version of
# Run.captureStdout() that could place decompressed files into the same
# generated directory.  So basically we're re-doing the ugly hacks from our old
# Makefile.am in here.
export TEST_CFDIR=$1
MMDB_SRC=$2
TEST_CPUS=$3
VERBOSE=$4
shift 4 # remainder of args are prove tests

# XXX TODO: warn user about submodule init if not present?
set -e

outdir="${TEST_CFDIR}/geoip"
for mmdb in GeoLite2-City-20141008.mmdb GeoLite2-Country-20141008.mmdb; do
    xz_base="${mmdb}.xz"
    xz_src="${MMDB_SRC}/${xz_base}"
    xz_dst="${outdir}/${xz_base}"
    final_dst="${outdir}/${mmdb}"
    if [ -e "${xz_src}" ]; then
        if [ ! -e "${xz_dst}" ]; then
            ln -sf "${xz_src}" "${xz_dst}"
        fi
	if [ ! -e "${final_dst}" ]; then
	    (cd "${outdir}" && xz -dkf "${xz_base}")
	fi
    fi
done

if [ "$VERBOSE" -eq "1" ]; then
    PROVE_ARGS="-v -f --merge --norc"
else
    PROVE_ARGS="-q -f --merge --norc -j${TEST_CPUS} --state=slow,save --statefile=.prove_gdtest"
fi
exec prove ${PROVE_ARGS} $@
