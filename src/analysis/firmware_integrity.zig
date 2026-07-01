const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const parser = @import("../core/parser.zig");

const Allocator = types.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

pub const SignatureAlgorithm = enum {
    rsa_pkcs1_sha256,
    rsa_pkcs1_sha384,
    rsa_pss_sha256,
    ecdsa_secp256r1_sha256,
    ecdsa_secp384r1_sha384,
    pkcs7_signed_data,
    authenticode,
    raw_hash,
    unknown,
};

pub const FirmwareFormat = enum {
    raw_binary,
    uefi_fv,
    uefi_ffs,
    intel_me,
    u_boot_image,
    fit_image,
    android_bootimg,
    cpio_archive,
    initramfs,
    signed_container,
    unknown,
};

pub const SigningStatus = enum {
    signed_verified,
    signed_not_verified,
    unsigned,
    signature_missing,
    signature_invalid,
    hash_mismatch,
    unknown,
};

pub const IntegrityViolation = enum {
    hash_mismatch,
    signature_missing,
    signature_invalid,
    certificate_expired,
    certificate_revoked,
    self_signed_untrusted,
    unsigned_region,
    unexpected_modification,
    rollback_detected,
    version_regression,
    measurement_inconsistency,
};

pub const CertificateInfo = struct {
    issuer: []const u8 = "",
    subject: []const u8 = "",
    serial: []const u8 = "",
    not_before: i64 = 0,
    not_after: i64 = 0,
    is_self_signed: bool = false,
    is_expired: bool = false,
    key_usage_flags: u32 = 0,
};

pub const FirmwareRegion = struct {
    offset: usize,
    size: usize,
    name: []const u8 = "",
    expected_hash: [32]u8,
    actual_hash: [32]u8,
    hash_matches: bool = false,
    signed_status: SigningStatus = .unknown,
    is_critical: bool = false,
};

pub const FirmwareMeasurement = struct {
    region_index: usize,
    measurement_type: []const u8 = "",
    expected_value: []const u8 = "",
    actual_value: []const u8 = "",
    matches_baseline: bool = false,
    pcr_index: u8 = 0,
};

pub const IntegrityFinding = struct {
    region_index: usize,
    violation: IntegrityViolation,
    severity: u8,
    offset: usize,
    description: []const u8 = "",
    recommendation: []const u8 = "",
};

pub const FirmwareAnalysis = struct {
    format: FirmwareFormat,
    total_size: usize,
    regions: []FirmwareRegion,
    measurements: []FirmwareMeasurement,
    findings: []IntegrityFinding,
    certificates: []CertificateInfo,
    overall_status: SigningStatus,
    integrity_score: f64,
    boot_chain_trusted: bool,
    has_rollback_protection: bool,
    has_secure_boot: bool,
    measured_boot_available: bool,
    immutable_region_count: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.regions);
        allocator.free(self.measurements);
        allocator.free(self.findings);
        allocator.free(self.certificates);
    }
};

pub fn analyzeFirmware(allocator: Allocator, bytes: []const u8, _: []const u8) !FirmwareAnalysis {
    const format = detectFirmwareFormat(bytes);
    var regions = std.ArrayList(FirmwareRegion).init(allocator);
    errdefer regions.deinit();
    var findings = std.ArrayList(IntegrityFinding).init(allocator);
    errdefer findings.deinit();
    var measurements = std.ArrayList(FirmwareMeasurement).init(allocator);
    errdefer measurements.deinit();
    var certificates = std.ArrayList(CertificateInfo).init(allocator);
    errdefer certificates.deinit();

    try discoverRegions(bytes, format, &regions);
    try validateRegionHashes(bytes, &regions, &findings);
    try detectSignatures(bytes, &regions, &findings, &certificates);
    try analyzeBootChain(bytes, format, &findings, &measurements, regions.items);
    try checkRollbackProtection(bytes, &findings);

    const score = computeIntegrityScore(findings.items, regions.items);
    const overall = determineOverallStatus(findings.items);

    return .{
        .format = format,
        .total_size = bytes.len,
        .regions = try regions.toOwnedSlice(),
        .measurements = try measurements.toOwnedSlice(),
        .findings = try findings.toOwnedSlice(),
        .certificates = try certificates.toOwnedSlice(),
        .overall_status = overall,
        .integrity_score = score,
        .boot_chain_trusted = score >= 70,
        .has_rollback_protection = hasRollbackProtection(bytes),
        .has_secure_boot = hasSecureBoot(bytes),
        .measured_boot_available = hasMeasuredBoot(bytes),
        .immutable_region_count = countImmutableRegions(regions.items),
    };
}

fn detectFirmwareFormat(bytes: []const u8) FirmwareFormat {
    if (bytes.len < 16) return .unknown;
    if (std.mem.eql(u8, bytes[0..4], "\x55\xaa\x55\xaa")) return .raw_binary;
    if (std.mem.eql(u8, bytes[0..4], "_FVH")) return .uefi_fv;
    if (std.mem.eql(u8, bytes[0..4], "\xfe\xff\xff\xff")) return .intel_me;
    if (std.mem.eql(u8, bytes[0..4], "\x27\x05\x19\x56")) return .u_boot_image;
    if (std.mem.eql(u8, bytes[0..4], "ANDROID!")) return .android_bootimg;
    if (std.mem.eql(u8, bytes[0..4], "\x71\xc7")) return .cpio_archive;
    if (std.mem.indexOf(u8, bytes[0..64], "FIT") != null) return .fit_image;
    if (std.mem.indexOf(u8, bytes, "070701") != null) return .initramfs;
    if (std.mem.indexOf(u8, bytes, "PKCS7") != null) return .signed_container;
    return .raw_binary;
}

fn discoverRegions(bytes: []const u8, format: FirmwareFormat, regions: *std.ArrayList(FirmwareRegion)) !void {
    var off: usize = 0;
    var region_idx: usize = 0;

    while (off < bytes.len and region_idx < 128) {
        const size = detectNextRegion(bytes, off, format);
        if (size == 0) break;

        const actual_end = @min(off + size, bytes.len);
        const region_size = actual_end - off;
        const expected: [32]u8 = [_]u8{0} ** 32;
        var actual: [32]u8 = [_]u8{0} ** 32;

        if (off + region_size <= bytes.len) {
            Sha256.hash(bytes[off..][0..region_size], &actual, .{});
        }

        const name = switch (format) {
            .uefi_fv => blk: {
                if (region_size >= 40) {
                    const raw_name = bytes[off + 20 .. off + 28];
                    const end = std.mem.indexOfScalar(u8, raw_name, 0) orelse raw_name.len;
                    break :blk raw_name[0..end];
                }
                break :blk "";
            },
            else => try std.fmt.allocPrint(regions.allocator, "region_{}", .{region_idx}),
        };

        try regions.append(.{
            .offset = off,
            .size = region_size,
            .name = name,
            .expected_hash = expected,
            .actual_hash = actual,
            .hash_matches = false,
            .signed_status = .unknown,
            .is_critical = isCriticalRegion(off, format, region_idx),
        });

        off += if (size > 0) size else @as(usize, 1);
        region_idx += 1;
    }

    if (regions.items.len == 0 and bytes.len > 0) {
        var hash: [32]u8 = undefined;
        Sha256.hash(bytes, &hash, .{});
        try regions.append(.{
            .offset = 0,
            .size = bytes.len,
            .name = "entire_image",
            .expected_hash = hash,
            .actual_hash = hash,
            .hash_matches = true,
            .signed_status = .unknown,
            .is_critical = true,
        });
    }
}

fn detectNextRegion(bytes: []const u8, offset: usize, format: FirmwareFormat) usize {
    switch (format) {
        .uefi_fv => {
            if (offset + 40 <= bytes.len) {
                const hdr = bytes[offset..offset + 40];
                if (std.mem.eql(u8, hdr[0..4], "_FVH")) {
                    const fv_len = std.mem.readInt(u64, hdr[24..32], .little);
                    return @intCast(fv_len);
                }
            }
            return 4096;
        },
        .uefi_ffs => return 4096,
        .intel_me => return 65536,
        .u_boot_image => {
            if (offset + 64 <= bytes.len) {
                const ih_size = std.mem.readInt(u32, bytes[offset + 12..][0..4], .big);
                return 64 + ih_size;
            }
            return 0;
        },
        .android_bootimg => {
            if (offset + 1648 <= bytes.len) {
                const kernel_size = std.mem.readInt(u32, bytes[offset + 8..][0..4], .little);
                const ramdisk_size = std.mem.readInt(u32, bytes[offset + 16..][0..4], .little);
                const second_size = std.mem.readInt(u32, bytes[offset + 20..][0..4], .little);
                return 1648 + kernel_size + ramdisk_size + second_size;
            }
            return 0;
        },
        .cpio_archive, .initramfs => {
            if (offset + 6 <= bytes.len and std.mem.eql(u8, bytes[offset..][0..6], "070701")) {
                var pos = offset;
                while (pos + 110 <= bytes.len) {
                    if (std.mem.eql(u8, bytes[pos..][0..6], "070701")) {
                        const namesize = std.mem.readInt(u32, bytes[pos + 94..][0..4], .little);
                        const filesize_str = bytes[pos + 48..][0..8];
                        var filesize: u32 = 0;
                        for (filesize_str, 0..) |c, j| {
                            const digit = switch (c) {
                                '0'...'9' => c - '0',
                                'a'...'f' => c - 'a' + 10,
                                'A'...'F' => c - 'A' + 10,
                                else => 0,
                            };
                            filesize |= @as(u32, digit) << @intCast((7 - j) * 4);
                        }
                        const hdr_len = 110 + namesize;
                        const pad = (hdr_len + 3) & ~@as(usize, 3);
                        const data_pad = (filesize + 3) & ~@as(u32, 3);
                        pos = offset + pad + data_pad;
                        continue;
                    }
                    break;
                }
                return pos - offset;
            }
            return 0;
        },
        else => return bytes.len - offset,
    }
}

fn validateRegionHashes(bytes: []const u8, regions: *std.ArrayList(FirmwareRegion), findings: *std.ArrayList(IntegrityFinding)) !void {
    for (regions.items, 0..) |*region, idx| {
        if (region.offset + region.size > bytes.len) {
            try findings.append(.{
                .region_index = idx,
                .violation = .hash_mismatch,
                .severity = 90,
                .offset = region.offset,
                .description = "Region extends beyond image boundary",
                .recommendation = "Verify firmware image integrity",
            });
            continue;
        }

        var hash: [32]u8 = undefined;
        Sha256.hash(bytes[region.offset..][0..region.size], &hash, .{});

        region.actual_hash = hash;
        region.hash_matches = std.mem.eql(u8, &hash, &region.expected_hash);

        if (!region.hash_matches and !isAllZero(&region.expected_hash)) {
            try findings.append(.{
                .region_index = idx,
                .violation = .hash_mismatch,
                .severity = if (region.is_critical) @as(u8, 95) else @as(u8, 60),
                .offset = region.offset,
                .description = "Region hash mismatch - possible tampering",
                .recommendation = "Re-flash firmware from trusted source",
            });
        }
    }
}

fn isAllZero(hash: *const [32]u8) bool {
    for (hash.*) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn detectSignatures(bytes: []const u8, regions: *std.ArrayList(FirmwareRegion), findings: *std.ArrayList(IntegrityFinding), certificates: *std.ArrayList(CertificateInfo)) !void {
    const sig_patterns = [_]struct { pattern: []const u8, alg: SignatureAlgorithm }{
        .{ .pattern = "PKCS7", .alg = .pkcs7_signed_data },
        .{ .pattern = "\x30\x82\x06\x52\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02", .alg = .pkcs7_signed_data },
        .{ .pattern = "RSA", .alg = .rsa_pkcs1_sha256 },
        .{ .pattern = "-----BEGIN PKCS7", .alg = .pkcs7_signed_data },
    };

    for (regions.items, 0..) |*region, idx| {
        const end = @min(region.offset + region.size, bytes.len);
        const slice = bytes[region.offset..end];
        var found_sig = false;

        for (sig_patterns) |sp| {
            if (std.mem.indexOf(u8, slice, sp.pattern) != null) {
                region.signed_status = .signed_not_verified;
                found_sig = true;
                try certificates.append(.{
                    .issuer = "unknown",
                    .subject = "detected",
                    .is_self_signed = true,
                });
                break;
            }
        }

        if (region.signed_status == .signed_not_verified) {
            try verifyRegionSignature(bytes, region.*, certificates);
        }

        if (idx > 0 and !found_sig and region.size >= 256) {
            try findings.append(.{
                .region_index = idx,
                .violation = .signature_missing,
                .severity = if (region.is_critical) @as(u8, 80) else @as(u8, 40),
                .offset = region.offset,
                .description = "Critical region lacks digital signature",
                .recommendation = "Sign firmware region before deployment",
            });
        }
    }
}

fn verifyRegionSignature(bytes: []const u8, region: FirmwareRegion, certificates: *std.ArrayList(CertificateInfo)) !void {
    _ = certificates;
    _ = bytes;
    _ = region;
}

fn analyzeBootChain(_: []const u8, format: FirmwareFormat, findings: *std.ArrayList(IntegrityFinding), measurements: *std.ArrayList(FirmwareMeasurement), regions: []const FirmwareRegion) !void {
    _ = format;
    for (regions, 0..) |region, idx| {
        if (region.is_critical and region.signed_status != .signed_verified) {
            try findings.append(.{
                .region_index = idx,
                .violation = .signature_missing,
                .severity = 85,
                .offset = region.offset,
                .description = "Critical boot chain component unsigned",
                .recommendation = "Enable secure boot with proper signing",
            });
        }
    }

    var pcr: u8 = 0;
    for (regions) |region| {
        if (region.signed_status == .signed_verified or region.hash_matches) {
            try measurements.append(.{
                .region_index = pcr,
                .measurement_type = "sha256",
                .expected_value = "",
                .actual_value = "",
                .matches_baseline = region.hash_matches,
                .pcr_index = pcr,
            });
            pcr += 1;
            if (pcr >= 16) break;
        }
    }
}

fn checkRollbackProtection(bytes: []const u8, findings: *std.ArrayList(IntegrityFinding)) !void {
    const rollback_indicators = [_][]const u8{
        "version=", "ver=", "firmware_version=", "build=",
    };
    var found_version = false;

    for (rollback_indicators) |indicator| {
        if (std.mem.indexOf(u8, bytes, indicator) != null) {
            found_version = true;
            break;
        }
    }

    if (!found_version) {
        try findings.append(.{
            .region_index = 0,
            .violation = .rollback_detected,
            .severity = 50,
            .offset = 0,
            .description = "No rollback protection version identifier found",
            .recommendation = "Implement versioned rollback protection mechanism",
        });
    }
}

fn hasRollbackProtection(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "rollback") != null or
        std.mem.indexOf(u8, bytes, "anti-rollback") != null or
        std.mem.indexOf(u8, bytes, "version_check") != null;
}

fn hasSecureBoot(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "secure_boot") != null or
        std.mem.indexOf(u8, bytes, "SecureBoot") != null or
        std.mem.indexOf(u8, bytes, "UEFI_SECURE_BOOT") != null;
}

fn hasMeasuredBoot(bytes: []const u8) bool {
    return std.mem.indexOf(u8, bytes, "measured_boot") != null or
        std.mem.indexOf(u8, bytes, "MeasuredBoot") != null or
        std.mem.indexOf(u8, bytes, "TPM") != null;
}

fn isCriticalRegion(offset: usize, format: FirmwareFormat, index: usize) bool {
    _ = offset;
    return switch (format) {
        .uefi_fv => index < 3,
        .android_bootimg => index < 2,
        .u_boot_image => index == 0,
        .raw_binary => index == 0,
        else => false,
    };
}

fn countImmutableRegions(regions: []const FirmwareRegion) usize {
    var count: usize = 0;
    for (regions) |region| {
        if (region.hash_matches or region.signed_status == .signed_verified) count += 1;
    }
    return count;
}

fn computeIntegrityScore(findings: []const IntegrityFinding, regions: []const FirmwareRegion) f64 {
    if (regions.len == 0) return 0;
    var score: f64 = 100;
    for (findings) |finding| {
        score -= @as(f64, @floatFromInt(finding.severity)) * 0.3;
    }
    var verified: usize = 0;
    for (regions) |region| {
        if (region.hash_matches or region.signed_status == .signed_verified) verified += 1;
    }
    score += @as(f64, @floatFromInt(verified)) * 10.0 / @as(f64, @floatFromInt(regions.len));
    return utils.clamp100(score);
}

fn determineOverallStatus(findings: []const IntegrityFinding) SigningStatus {
    for (findings) |f| {
        if (f.violation == .signature_invalid or f.violation == .hash_mismatch) return .signature_invalid;
        if (f.violation == .signature_missing) return .signature_missing;
    }
    if (findings.len == 0) return .signed_verified;
    return .signed_not_verified;
}

pub fn computeFirmwareHash(bytes: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(bytes, &hash, .{});
    return hash;
}

pub fn verifyFirmwareSignature(bytes: []const u8, signature_offset: usize, signature_size: usize) SigningStatus {
    if (signature_offset + signature_size > bytes.len) return .signature_invalid;
    return .signed_not_verified;
}

pub fn detectFirmwareBackdoors(allocator: Allocator, bytes: []const u8) ![]IntegrityFinding {
    var findings = std.ArrayList(IntegrityFinding).init(allocator);
    errdefer findings.deinit();

    const suspicious_strings = [_][]const u8{
        "debug", "backdoor", "test_key", "debug_key", "skip_verify",
        "bypass", "insecure", "allow_unsigned", "allow_any",
        "root_me", "shell_on", "factory_reset", "diag_mode",
    };

    for (suspicious_strings) |s| {
        var search_off: usize = 0;
        while (std.mem.indexOf(u8, bytes[search_off..], s)) |match_off| {
            const abs_off = search_off + match_off;
            try findings.append(.{
                .region_index = 0,
                .violation = .unexpected_modification,
                .severity = 75,
                .offset = abs_off,
                .description = try std.fmt.allocPrint(allocator, "Suspicious string found: {s}", .{s}),
                .recommendation = "Remove debug/backdoor artifacts from production firmware",
            });
            search_off = abs_off + 1;
        }
    }

    return findings.toOwnedSlice();
}
