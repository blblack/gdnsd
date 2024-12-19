// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2024 Brandon L Black <blblack@gmail.com>

const std = @import("std");
const assert = std.debug.assert;

const c = @cImport({
    @cInclude("config.h");
    @cInclude("gdnsd/log.h");
    @cInclude("gdnsd/net.h");
    @cInclude("proxy.h");
});

// Note XXX: it's possible the old version of this allowed >108 total bytes
// with v2 and extra TLVs.  Later, when dnsio_tcp is also converted to Zig,
// should make more of the recv buffer union available for TLV use.  For now,
// we explicitly limit to the union size, leaving 56 bytes for potential TLVs.
const max_proxy_data = @sizeOf(c.union_proxy_hdr);

fn parse_proxy_v1(asp: *c.struct_anysin, v1: []u8) usize {
    // PROXYv1 requires 8-108 bytes starting with "PROXY "
    if (v1.len < 8 or v1.len > max_proxy_data or !std.mem.eql(u8, v1[0..6], "PROXY "))
        return 0;

    // Find terminal "\r\n"
    const v1_term = std.mem.indexOf(u8, v1, "\r\n");
    if (v1_term == null)
        return 0;

    // How many bytes we will consume in the success case (incl terminal \r\n)
    const v1_bytes = v1_term.? + 2;

    // Space-splitting on the part between "PROXY " and "\r\n"
    var it = std.mem.splitScalar(u8, v1[6..v1_term.?], ' ');

    // Proto must be "TCP4" or "TCP6"
    const proto = it.next();
    if (proto == null or proto.?.len != 4 or (!std.mem.eql(u8, proto.?, "TCP4") and !std.mem.eql(u8, proto.?, "TCP6")))
        return 0;

    // Address fields just require 1+ bytes each.  getaddrinfo() will parse more-deeply later.
    const srcaddr = it.next();
    if (srcaddr == null or srcaddr.?.len == 0)
        return 0;
    const dstaddr = it.next();
    if (dstaddr == null or dstaddr.?.len == 0)
        return 0;
    const srcport = it.next();
    if (srcport == null or srcport.?.len == 0)
        return 0;
    const dstport = it.next();
    if (dstport == null or dstport.?.len == 0)
        return 0;

    // No more fields allowed!
    if (it.next() != null)
        return 0;

    // Convert srcaddr and srcport to C strings on the stack
    var srcaddr_c: [108:0]u8 = undefined;
    var srcport_c: [108:0]u8 = undefined;
    @memcpy(srcaddr_c[0..srcaddr.?.len], srcaddr.?);
    srcaddr_c[srcaddr.?.len] = 0;
    @memcpy(srcport_c[0..srcport.?.len], srcport.?);
    srcport_c[srcport.?.len] = 0;

    // Convert to anysin with getaddrinfo
    const addr_err: c_int = c.gdnsd_anysin_getaddrinfo(&srcaddr_c, &srcport_c, asp);
    if (addr_err != 0)
        return 0;

    return v1_bytes;
}

fn proxy_parse_v2(asp: *c.struct_anysin, hdrp: *c.union_proxy_hdr, dlen: usize) usize {
    const fam_v4: u8 = 0x11;
    const fam_v6: u8 = 0x21;
    const ver_mask: u8 = 0xF0;
    const ver_v2: u8 = 0x20;
    const cmd_mask: u8 = 0x0F;
    const cmd_proxy: u8 = 0x01;
    const meta_size = @sizeOf(@TypeOf(hdrp.*.v2.meta));
    const ipv4_size = @sizeOf(@TypeOf(hdrp.*.v2.ip.v4));
    const ipv6_size = @sizeOf(@TypeOf(hdrp.*.v2.ip.v6));
    const proxy_v2sig = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

    // Basic PROXYv2 metadata block
    if (dlen < meta_size)
        return 0;
    if (!std.mem.eql(u8, &hdrp.*.v2.meta.sig, proxy_v2sig))
        return 0;
    if (hdrp.*.v2.meta.ver_cmd & ver_mask != ver_v2)
        return 0;
    const v2_bytes = meta_size + std.mem.bigToNative(u16, hdrp.*.v2.meta.data_len);
    if (dlen < v2_bytes)
        return 0;
    if (hdrp.*.v2.meta.ver_cmd & cmd_mask != cmd_proxy)
        return 0;

    // Consume address fields per-family, if enough data exists
    @memset(std.mem.asBytes(asp), 0);
    if (hdrp.*.v2.meta.fam == fam_v4 and v2_bytes >= meta_size + ipv4_size) { // TCPv4
        asp.*.s.sin4.sin_family = c.AF_INET;
        asp.*.s.sin4.sin_addr.s_addr = hdrp.*.v2.ip.v4.src_addr;
        asp.*.s.sin4.sin_port = hdrp.*.v2.ip.v4.src_port;
        asp.*.len = @sizeOf(c.struct_sockaddr_in);
    } else if (hdrp.*.v2.meta.fam == fam_v6 and v2_bytes >= meta_size + ipv6_size) { // TCPv6
        asp.*.s.sin6.sin6_family = c.AF_INET6;
        asp.*.s.sin6.sin6_addr = @as(@TypeOf(asp.*.s.sin6.sin6_addr), @bitCast(hdrp.*.v2.ip.v6.src_addr));
        asp.*.s.sin6.sin6_port = hdrp.*.v2.ip.v6.src_port;
        asp.*.len = @sizeOf(c.struct_sockaddr_in6);
    } else {
        return 0;
    }

    return v2_bytes;
}

pub export fn proxy_parse(asp: *c.struct_anysin, hdrp: *c.union_proxy_hdr, rlen: usize) usize {
    const dlen = @min(rlen, max_proxy_data);
    const v2_bytes = proxy_parse_v2(asp, hdrp, dlen);
    if (v2_bytes != 0)
        return v2_bytes;
    return parse_proxy_v1(asp, hdrp.*.v1_line[0..dlen]);
}
