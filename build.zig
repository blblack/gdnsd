// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

const std = @import("std");
const assert = std.debug.assert;
const Build = std.Build;
const mem = std.mem;

// Top-level package metadata
const pkg_version: std.SemanticVersion = .{ .major = 3, .minor = 99, .patch = 1, .pre = "alpha10" };
const pkg_name = "gdnsd";
const pkg_url = "https://gdnsd.org";
const pkg_bug = "https://github.com/gdnsd/gdnsd/issues";

// The major/minor/patch must be in the range (0-255) for csock protocol use as unsigned bytes.
comptime {
    assert(pkg_version.major <= 255);
    assert(pkg_version.minor <= 255);
    assert(pkg_version.patch <= 255);
}

// Common installation path data
const InstPaths = struct {
    // These are just convenience refs to installation dirs
    abs_bindir: []const u8,
    abs_sbindir: []const u8,
    mandir: []const u8, // prefix-relative!
    // These paths are not for actual installation of generated files.  We just
    // create them as empty, and they get hardcoded into binaries via config.h
    // as default paths that can be overriden by runtime CLI/config
    def_config: []const u8,
    def_libexec: []const u8,
    def_run: []const u8,
    def_state: []const u8,
};

// Common configuration bits
const BuildCfg = struct {
    optimize: std.builtin.OptimizeMode,
    target: Build.ResolvedTarget,
    test_cpus: usize,
    use_geoip2: bool,
    use_gnutls: bool,
};

// Common build deps
const BuildCommon = struct {
    config_h: *Build.Step.ConfigHeader,
    libgdnsd: *Build.Step.Compile,
    libgdmaps: *Build.Step.Compile,
    shlibs: std.ArrayList([]const u8),
};

const warn_cflags: []const []const u8 = &.{
    // Lots of warnings, enforced as errors.  Currently zig uses clang-19,
    // so we can target that exactly and not worry about other compilers.
    "-Werror",
    "-Wall",
    "-Wextra",
    "-Walloca",
    "-Wbad-function-cast",
    "-Wcast-align",
    "-Wcast-qual",
    "-Wdate-time",
    "-Wdouble-promotion",
    "-Wvla",
    "-Wfloat-equal",
    "-Wfloat-conversion",
    "-Wformat-signedness",
    "-Wmissing-include-dirs",
    "-Wmissing-prototypes",
    "-Wpointer-arith",
    "-Wshadow-all",
    "-Wsign-conversion",
    "-Wstrict-prototypes",
    "-Wswitch-default",
    "-Wswitch-enum",
    "-Wundef",
    "-Wunused",
};

fn build_config_h(b: *Build, bcfg: BuildCfg, ipaths: InstPaths) !*Build.Step.ConfigHeader {
    const feats_str = b.fmt("{s}{s}{s}", .{
        @tagName(bcfg.optimize),
        if (bcfg.use_geoip2) " geoip2" else "",
        if (bcfg.use_gnutls) " gnutls" else "",
    });

    return b.addConfigHeader(.{
        .style = .{ .autoconf = b.path("config.h.in") },
        .include_path = "config.h",
    }, .{
        // package metadata
        .PACKAGE_NAME = pkg_name,
        .PACKAGE_URL = pkg_url,
        .PACKAGE_BUGREPORT = pkg_bug,
        .PACKAGE_VERSION = b.fmt("{}", .{pkg_version}),
        .PACKAGE_V_MAJOR = @as(u8, @intCast(pkg_version.major)),
        .PACKAGE_V_MINOR = @as(u8, @intCast(pkg_version.minor)),
        .PACKAGE_V_PATCH = @as(u8, @intCast(pkg_version.patch)),
        .BUILD_INFO = try get_build_info(b),
        .BUILD_FEATURES = feats_str,
        // optional libraries that code needs to be aware of
        .HAVE_LIBUNWIND = null, // skipping unwind for now
        .HAVE_GEOIP2 = if (bcfg.use_geoip2) true else null,
        .HAVE_GNUTLS = if (bcfg.use_gnutls) true else null,
        // Things that depend on target cpu stuff:
        .SIZEOF_UINTPTR_T = bcfg.target.result.ptrBitWidth() / 8,
        .CACHE_ALIGN = std.atomic.cacheLineForCpu(bcfg.target.result.cpu),
        // Paths the runtime hardcodes as defaults
        .GDNSD_DEFPATH_CONFIG = ipaths.def_config,
        .GDNSD_DEFPATH_LIBEXEC = ipaths.def_libexec,
        .GDNSD_DEFPATH_RUN = ipaths.def_run,
        .GDNSD_DEFPATH_STATE = ipaths.def_state,
        // This allows userspace-rcu to inline more things
        ._LGPL_SOURCE = 1,
        // AC_USE_SYSTEM_EXTENSIONS gave all of these, and many of them may be
        // irrelevant, esp on mainstream platforms, but we can live with them
        // for now.  I deleted a few that didn't seem worth it, but kept most.
        // I think mostly we'll be focused on Linux/*BSD until most/all code is
        // transitioned to Zig, then worry more about portability again.
        ._ALL_SOURCE = 1,
        ._DARWIN_C_SOURCE = 1,
        .__EXTENSIONS__ = 1,
        ._GNU_SOURCE = 1,
        ._NETBSD_SOURCE = 1,
        ._OPENBSD_SOURCE = 1,
        .__STDC_WANT_IEC_60559_ATTRIBS_EXT__ = 1,
        .__STDC_WANT_IEC_60559_BFP_EXT__ = 1,
        .__STDC_WANT_IEC_60559_DFP_EXT__ = 1,
        .__STDC_WANT_IEC_60559_EXT__ = 1,
        .__STDC_WANT_IEC_60559_FUNCS_EXT__ = 1,
        .__STDC_WANT_IEC_60559_TYPES_EXT__ = 1,
        .__STDC_WANT_LIB_EXT2__ = 1,
        .__STDC_WANT_MATH_SPEC_FUNCS__ = 1,
    });
}

fn add_common_incs(c: *Build.Step.Compile, ch: *Build.Step.ConfigHeader) void {
    const b = c.step.owner;
    c.addIncludePath(b.path("src"));
    c.addIncludePath(b.path("include"));
    c.addConfigHeader(ch);
}

fn ragel_gen(b: *Build, in: []const u8, out: []const u8, flag: []const u8) Build.LazyPath {
    const gen = b.addSystemCommand(&.{ "ragel", flag, "-o" });
    const rv = gen.addOutputFileArg(out);
    gen.addFileArg(b.path(in));
    gen.expectExitCode(0);
    return rv;
}

fn build_libgdnsd(b: *Build, bcfg: BuildCfg, config_h: *Build.Step.ConfigHeader) *Build.Step.Compile {
    const libgdnsd = b.addStaticLibrary(.{
        .name = "gdnsd",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
        .link_libc = true,
    });
    add_common_incs(libgdnsd, config_h);
    libgdnsd.addCSourceFile(.{
        .file = ragel_gen(b, "libgdnsd/vscf.rl", "libgdnsd/vscf.c", "-T0"),
        .flags = warn_cflags,
    });
    libgdnsd.addCSourceFiles(.{
        .files = &.{
            "libgdnsd/dname.c",
            "libgdnsd/net.c",
            "libgdnsd/log.c",
            "libgdnsd/misc.c",
            "libgdnsd/paths.c",
            "libgdnsd/file.c",
            "libgdnsd/alloc.c",
            "libgdnsd/gstrerrorr.c",
        },
        .flags = warn_cflags,
    });
    return libgdnsd;
}

fn build_libgdmaps(b: *Build, bcfg: BuildCfg, config_h: *Build.Step.ConfigHeader) *Build.Step.Compile {
    const libgdmaps = b.addStaticLibrary(.{
        .name = "gdmaps",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
        .link_libc = true,
    });
    add_common_incs(libgdmaps, config_h);
    libgdmaps.addCSourceFiles(.{
        .files = &.{
            "libgdmaps/gdmaps.c",
            "libgdmaps/dcinfo.c",
            "libgdmaps/dclists.c",
            "libgdmaps/dcmap.c",
            "libgdmaps/nlist.c",
            "libgdmaps/ntree.c",
            "libgdmaps/nets.c",
            "libgdmaps/gdgeoip2.c",
        },
        .flags = warn_cflags,
    });
    return libgdmaps;
}

fn build_gdnsd_dnssec_bench(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    const gdnsd_dnssec_bench = b.addExecutable(.{
        .name = "gdnsd_dnssec_bench",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(gdnsd_dnssec_bench, bcom.config_h);
    for (bcom.shlibs.items) |s| gdnsd_dnssec_bench.linkSystemLibrary(s);
    gdnsd_dnssec_bench.linkLibrary(bcom.libgdnsd);
    gdnsd_dnssec_bench.addCSourceFiles(.{
        .files = &.{
            "src/dnssec_bench.c",
            "src/dnssec_alg.c",
        },
        .flags = warn_cflags,
    });
    b.installArtifact(gdnsd_dnssec_bench);
}

fn build_gdnsdctl(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    const gdnsdctl = b.addExecutable(.{
        .name = "gdnsdctl",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(gdnsdctl, bcom.config_h);
    for (bcom.shlibs.items) |s| gdnsdctl.linkSystemLibrary(s);
    gdnsdctl.linkLibrary(bcom.libgdnsd);
    gdnsdctl.addCSourceFiles(.{
        .files = &.{
            "src/gdnsdctl.c",
            "src/csc.c",
        },
        .flags = warn_cflags,
    });
    b.installArtifact(gdnsdctl);
}

fn build_gdnsd_geoip_test(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    const gdnsd_geoip_test = b.addExecutable(.{
        .name = "gdnsd_geoip_test",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(gdnsd_geoip_test, bcom.config_h);
    for (bcom.shlibs.items) |s| gdnsd_geoip_test.linkSystemLibrary(s);
    gdnsd_geoip_test.linkLibrary(bcom.libgdnsd);
    gdnsd_geoip_test.linkLibrary(bcom.libgdmaps);
    gdnsd_geoip_test.addCSourceFile(.{
        .file = b.path("src/plugins/gdnsd_geoip_test.c"),
        .flags = warn_cflags,
    });
    b.installArtifact(gdnsd_geoip_test);
}

fn build_gdnsd_extmon_helper(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    const gdnsd_extmon_helper = b.addExecutable(.{
        .name = "gdnsd_extmon_helper",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(gdnsd_extmon_helper, bcom.config_h);
    for (bcom.shlibs.items) |s| gdnsd_extmon_helper.linkSystemLibrary(s);
    gdnsd_extmon_helper.linkLibrary(bcom.libgdnsd);
    gdnsd_extmon_helper.addCSourceFiles(.{
        .files = &.{
            "src/plugins/extmon_helper.c",
            "src/plugins/extmon_comms.c",
        },
        .flags = warn_cflags,
    });
    const helper_exe = b.addInstallArtifact(gdnsd_extmon_helper, .{ .dest_dir = .{ .override = .{ .custom = "libexec/gdnsd" } } });
    b.getInstallStep().dependOn(&helper_exe.step);
}

fn build_gdnsd(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    const gdnsd = b.addExecutable(.{
        .name = "gdnsd",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(gdnsd, bcom.config_h);
    for (bcom.shlibs.items) |s| gdnsd.linkSystemLibrary(s);
    gdnsd.linkLibrary(bcom.libgdnsd);
    gdnsd.linkLibrary(bcom.libgdmaps);
    gdnsd.addCSourceFile(.{
        .file = ragel_gen(b, "src/zscan_rfc1035.rl", "src/zscan_rfc1035.c", "-G2"),
        .flags = warn_cflags,
    });
    gdnsd.addCSourceFiles(.{
        .files = &.{
            "src/main.c",
            "src/daemon.c",
            "src/csc.c",
            "src/css.c",
            "src/conf.c",
            "src/chal.c",
            "src/comp.c",
            "src/cookie.c",
            "src/zsrc_rfc1035.c",
            "src/ltree.c",
            "src/dnspacket.c",
            "src/dnsio_udp.c",
            "src/dnsio_tcp.c",
            "src/dnssec.c",
            "src/dnssec_alg.c",
            "src/dnssec_nxdc.c",
            "src/proxy.c",
            "src/socks.c",
            "src/statio.c",
            "src/plugins/extmon_comms.c",
            "src/plugins/http_status.c",
            "src/plugins/multifo.c",
            "src/plugins/null.c",
            "src/plugins/reflect.c",
            "src/plugins/simplefo.c",
            "src/plugins/static.c",
            "src/plugins/tcp_connect.c",
            "src/plugins/weighted.c",
            "src/plugins/extfile.c",
            "src/plugins/geoip.c",
            "src/plugins/metafo.c",
            "src/plugins/extmon.c",
            "src/plugins/mon.c",
            "src/plugins/plugapi.c",
        },
        .flags = warn_cflags,
    });
    const gdnsd_exe = b.addInstallArtifact(gdnsd, .{ .dest_dir = .{ .override = .{ .custom = "sbin" } } });
    b.getInstallStep().dependOn(&gdnsd_exe.step);
}

fn install_empty_dir(b: *Build, dpath: []const u8) void {
    const mkdir = b.addSystemCommand(&.{ "mkdir", "-p", dpath });
    b.getInstallStep().dependOn(&mkdir.step);
}

fn defpath_abs_or_rel(b: *Build, p: []const u8) []const u8 {
    if (p[0] == '/')
        return p;
    return b.getInstallPath(.prefix, p);
}

fn get_build_info(b: *Build) ![]const u8 {
    if (b.option([]const u8, "build-info", "Overrides the 'Build Info' string which is output by built binaries and normally contains version info derived from the git metadata")) |binfo|
        return binfo;
    var code: u8 = undefined;
    const r = b.build_root.path orelse ".";
    const desc_raw = b.runAllowFail(&[_][]const u8{
        "git", "-C", r, "describe", "--match", "v[0-9]*.[0-9]*.[0-9]*", "--abbrev=9",
    }, &code, .Ignore) catch {
        return try b.allocator.dupe(u8, "unknown");
    };
    return mem.trim(u8, desc_raw, " \n\r");
}

fn template_with_paths(b: *Build, gp: InstPaths, in: []const u8) Build.LazyPath {
    const gen = b.addSystemCommand(&.{"sed"});
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_BINDIR[@]|{s}|g", .{gp.abs_bindir}) });
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_SBINDIR[@]|{s}|g", .{gp.abs_sbindir}) });
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_DEFPATH_CONFIG[@]|{s}|g", .{gp.def_config}) });
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_DEFPATH_LIBEXEC[@]|{s}|g", .{gp.def_libexec}) });
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_DEFPATH_RUN[@]|{s}|g", .{gp.def_run}) });
    gen.addArgs(&.{ "-e", b.fmt("s|@GDNSD_DEFPATH_STATE[@]|{s}|g", .{gp.def_state}) });
    gen.setStdIn(.{ .lazy_path = b.path(in) });
    gen.expectExitCode(0);
    return gen.captureStdOut();
}

fn install_template_with_paths(b: *Build, gp: InstPaths, in: []const u8, out: []const u8) void {
    const generated = template_with_paths(b, gp, in);
    const inst = b.addInstallFileWithDir(generated, .prefix, out);
    b.getInstallStep().dependOn(&inst.step);
}

fn install_manpage_with_paths(b: *Build, gp: InstPaths, in: []const u8, section: []const u8) !void {
    assert(mem.endsWith(u8, in, ".podin")); // important for in_stem below
    const in_base = std.fs.path.basename(in);
    const in_stem = in_base[0..(in_base.len - 6)];
    const pod_tmp = template_with_paths(b, gp, in);

    // Creates e.g. zig-out/share/man/man8/gdnsd.zonefile.8
    {
        const gen = b.addSystemCommand(&.{"pod2man"});
        gen.addArg(b.fmt("--section={s}", .{section}));
        gen.addArg(b.fmt("--release={s} {}", .{ pkg_name, pkg_version }));
        gen.addArg(b.fmt("--center={s}", .{pkg_name}));
        gen.addFileArg(pod_tmp);
        gen.expectExitCode(0);
        const out_man_fn = b.fmt("{s}.{s}", .{ in_stem, section });
        const man_out_subpath = b.fmt("{s}/man{s}/{s}", .{ gp.mandir, section, out_man_fn });
        const generated = gen.addOutputFileArg(out_man_fn);
        const inst = b.addInstallFileWithDir(generated, .prefix, man_out_subpath);
        b.getInstallStep().dependOn(&inst.step);
    }

    // Creates e.g. zig-out/docs/GdnsdZonefile.pod
    var wiki_fn = std.ArrayList(u8).init(b.allocator);
    try wiki_fn.appendSlice("docs/");
    var it = mem.tokenizeAny(u8, in_stem, "_-.");
    while (it.next()) |tok| {
        try wiki_fn.append(std.ascii.toUpper(tok[0]));
        try wiki_fn.appendSlice(tok[1..tok.len]);
    }
    try wiki_fn.appendSlice(".pod");
    const inst = b.addInstallFileWithDir(pod_tmp, .prefix, wiki_fn.items);
    b.getInstallStep().dependOn(&inst.step);
}

// Legacy libgdmaps tests.  These are built from C, use libtap, and are helped
// by a shellscript that decompresses some optional large binary test data into
// a zig cache dir and then runs prove to drive them.
fn build_gdmaps_tests(b: *Build, bcfg: BuildCfg, bcom: BuildCommon) void {
    // Temp dir in cache for .nets + mmdb files as testsuite data (copied/decomped)
    const gdt_wf = b.addWriteFiles();
    _ = gdt_wf.addCopyDirectory(b.path("t/libgdmaps/tdata"), "geoip", .{ .include_extensions = &.{".nets"} });

    // Run the runtests script.  Needs args for the built test executables added further down.
    const gdt_run = Build.Step.Run.create(b, "run gdmaps tests");
    gdt_run.addArgs(&.{b.path("t/libgdmaps/runtests.sh").getPath(b)});
    gdt_run.addFileArg(gdt_wf.getDirectory());
    gdt_run.addFileArg(b.path("t/libgdmaps/gdnsd-geoip-testdata-v3"));
    gdt_run.addArg(b.fmt("{d}", .{bcfg.test_cpus}));
    if (b.verbose) {
        gdt_run.addArg("1");
    } else {
        gdt_run.addArg("0");
    }

    // Common static archive of libtap + gdmaps_test + libgdnsd + libgdmaps
    const libgdmaps_test = b.addStaticLibrary(.{
        .name = "gdmaps_test",
        .target = bcfg.target,
        .optimize = bcfg.optimize,
    });
    add_common_incs(libgdmaps_test, bcom.config_h);
    libgdmaps_test.addIncludePath(b.path("t/libtap"));
    libgdmaps_test.linkLibrary(bcom.libgdnsd);
    libgdmaps_test.linkLibrary(bcom.libgdmaps);
    libgdmaps_test.addCSourceFiles(.{
        .files = &.{
            "t/libtap/tap.c",
            "t/libgdmaps/gdmaps_test.c",
        },
        .flags = warn_cflags,
    });

    const tlist: []const []const u8 = &.{
        "t50_g2_country",
        "t51_g2_city",
        "t52_g2_nets",
        "t53_g2_cityauto",
        "t54_g2_complex",
        "t55_g2_def2",
        "t56_g2_defnone",
        "t57_g2_castatdef",
        "t58_g2_missingcoords",
        "t59_g2_extnets",
        "t60_g2_gn_corner",
        "t15_nogeo",
        "t17_extn_empty",
        "t18_extn_all",
        "t21_extn_subs",
        "t22_nets_corner",
    };

    for (tlist) |tname| {
        const tbin = b.addExecutable(.{
            .name = b.fmt("{s}.t", .{tname}),
            .target = bcfg.target,
            .optimize = bcfg.optimize,
        });
        add_common_incs(tbin, bcom.config_h);
        tbin.addIncludePath(b.path("t/libtap"));
        for (bcom.shlibs.items) |s| tbin.linkSystemLibrary(s);
        tbin.linkLibrary(libgdmaps_test);
        tbin.addCSourceFile(.{
            .file = b.path(b.fmt("t/libgdmaps/{s}.c", .{tname})),
            .flags = warn_cflags,
        });
        gdt_run.addFileArg(tbin.getEmittedBin());
    }

    // Top-level CLI step
    const gdt_step = b.step("gdtest", "Run gdmaps tests");
    gdt_step.dependOn(&gdt_run.step);
}

// Legacy integration testsuite, all Perl code run via "prove", runs gdmaps
// tests as part of the same action
fn build_integration_tests(b: *Build, bcfg: BuildCfg) void {
    const itest_step = b.step("itest", "Run integration tests");
    const itest_run = Build.Step.Run.create(b, "run integration tests");
    itest_step.dependOn(&itest_run.step);
    itest_run.step.dependOn(b.getInstallStep());

    const tpath = b.path("t").getPath(b);
    const tpatt_opt = b.option([]const u8, "tpattern", "Integration testfile pattern to execute verbosely, e.g. '004misc/*.t'");
    if (tpatt_opt) |tpatt| {
        itest_run.addArgs(&.{ "sh", "-c", b.fmt("prove -v -f --merge --norc -I {s} {s}/{s}", .{ tpath, tpath, tpatt }) });
    } else if (b.verbose) {
        itest_run.addArgs(&.{ "sh", "-c", b.fmt("prove -v -f --merge --norc -I {s} {s}/[0-9]*/*.t", .{ tpath, tpath }) });
    } else {
        itest_run.addArgs(&.{ "sh", "-c", b.fmt("prove -q -f --merge --norc -j{d} --state=slow,save --statefile=.prove_itest -I {s} {s}/[0-9]*/*.t", .{ bcfg.test_cpus, tpath, tpath }) });
    }
    itest_run.setEnvironmentVariable("PREFIX", b.install_prefix);
    itest_run.setEnvironmentVariable("TESTOUT_DIR", b.path("t/testout").getPath(b));
    const tpstart: u16 = b.option(u16, "test_port_start", "The integration test suite will use ~200 consecutive IP port numbers on '127.0.0.1' and '::1' starting at this value, default 12345") orelse 12345;
    itest_run.setEnvironmentVariable("TESTPORT_START", b.fmt("{d}", .{tpstart}));
    if (b.option(bool, "slow_tests", "Run slow integration tests, default false") orelse false)
        itest_run.setEnvironmentVariable("SLOW_TESTS", "1");
}

fn install_docs(b: *Build, gp: InstPaths) !void {
    install_template_with_paths(b, gp, "init/gdnsd.init.tmpl", "init/gdnsd.init");
    install_template_with_paths(b, gp, "init/gdnsd.service.tmpl", "init/gdnsd.service");
    const manpages = std.StaticStringMap([]const u8).initComptime(.{
        .{ "docs/gdnsd_geoip_test.podin", "1" },
        .{ "docs/gdnsd.config.podin", "5" },
        .{ "docs/gdnsd.zonefile.podin", "5" },
        .{ "docs/gdnsd.podin", "8" },
        .{ "docs/gdnsdctl.podin", "8" },
        .{ "docs/gdnsdctl.podin", "8" },
        .{ "docs/gdnsd-plugin-extfile.podin", "8" },
        .{ "docs/gdnsd-plugin-extmon.podin", "8" },
        .{ "docs/gdnsd-plugin-geoip.podin", "8" },
        .{ "docs/gdnsd-plugin-http_status.podin", "8" },
        .{ "docs/gdnsd-plugin-metafo.podin", "8" },
        .{ "docs/gdnsd-plugin-multifo.podin", "8" },
        .{ "docs/gdnsd-plugin-null.podin", "8" },
        .{ "docs/gdnsd-plugin-reflect.podin", "8" },
        .{ "docs/gdnsd-plugin-simplefo.podin", "8" },
        .{ "docs/gdnsd-plugin-static.podin", "8" },
        .{ "docs/gdnsd-plugin-tcp_connect.podin", "8" },
        .{ "docs/gdnsd-plugin-weighted.podin", "8" },
    });
    for (manpages.keys()) |k|
        try install_manpage_with_paths(b, gp, k, manpages.get(k).?);
}

fn make_shlibs_list(b: *Build, bcfg: BuildCfg) !std.ArrayList([]const u8) {
    var shlibs = try std.ArrayList([]const u8).initCapacity(b.allocator, 8);
    try shlibs.appendSlice(&.{ "urcu-qsbr", "ev", "sodium" });
    if (bcfg.use_geoip2)
        try shlibs.append("maxminddb");
    if (bcfg.use_gnutls)
        try shlibs.append("gnutls");
    return shlibs;
}

pub fn build(b: *Build) !void {
    // Initial meta-config
    const bcfg = BuildCfg{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
        .test_cpus = @max(std.Thread.getCpuCount() catch 1, 1), // Why can't we get access to zig's -jN?
        .use_geoip2 = b.option(bool, "use-geoip2", "Use libmaxminddb for geoip2 lookups (def: true)") orelse true,
        .use_gnutls = b.option(bool, "use-gnutls", "Use libgnutls for DNSSEC P256 support (def: true)") orelse true,
    };

    // Installation paths that other parts need
    const ipaths = InstPaths{
        .abs_bindir = b.getInstallPath(.bin, ""),
        .abs_sbindir = b.getInstallPath(.{ .custom = "sbin" }, ""),
        .mandir = "share/man",
        .def_config = defpath_abs_or_rel(b, b.option([]const u8, "defpath_config", "Absolute or prefix-relative default gdnsd config dir, default 'etc/gdnsd'") orelse "etc/gdnsd"),
        .def_libexec = defpath_abs_or_rel(b, b.option([]const u8, "defpath_libexec", "Absolute or prefix-relative default gdnsd libexec dir, default 'libexec/gdnsd'") orelse "libexec/gdnsd"),
        .def_run = defpath_abs_or_rel(b, b.option([]const u8, "defpath_run", "Absolute or prefix-relative default gdnsd run dir, default 'var/run/gdnsd'") orelse "var/run/gdnsd"),
        .def_state = defpath_abs_or_rel(b, b.option([]const u8, "defpath_state", "Absolute or prefix-relative default gdnsd state dir, default 'var/lib/gdnsd'") orelse "var/lib/gdnsd"),
    };

    // Common things all the executable builds need
    const config_h = try build_config_h(b, bcfg, ipaths);
    const bcom = BuildCommon{
        .config_h = config_h,
        .libgdnsd = build_libgdnsd(b, bcfg, config_h),
        .libgdmaps = build_libgdmaps(b, bcfg, config_h),
        .shlibs = try make_shlibs_list(b, bcfg),
    };

    // Installed executables
    build_gdnsd_extmon_helper(b, bcfg, bcom);
    build_gdnsd_dnssec_bench(b, bcfg, bcom);
    build_gdnsd_geoip_test(b, bcfg, bcom);
    build_gdnsdctl(b, bcfg, bcom);
    build_gdnsd(b, bcfg, bcom);

    // Tests
    build_gdmaps_tests(b, bcfg, bcom);
    build_integration_tests(b, bcfg);

    // Docs + empty installdirs
    try install_docs(b, ipaths);
    install_empty_dir(b, b.pathJoin(&.{ ipaths.def_config, "zones" }));
    install_empty_dir(b, b.pathJoin(&.{ ipaths.def_config, "geoip" }));
    install_empty_dir(b, ipaths.def_libexec);
    install_empty_dir(b, ipaths.def_run);
    install_empty_dir(b, ipaths.def_state);
}
