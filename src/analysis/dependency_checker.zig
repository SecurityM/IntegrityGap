const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const parser = @import("../core/parser.zig");

const Allocator = types.Allocator;
const BinaryImage = types.BinaryImage;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const DependencyType = enum {
    shared_library,
    static_library,
    framework,
    system_module,
    package,
    nuget_package,
    npm_package,
    cargo_crate,
    python_package,
    jar_archive,
    unknown,
};

pub const VulnerabilitySeverity = enum {
    none,
    low,
    medium,
    high,
    critical,
};

pub const VulnerabilityInfo = struct {
    cve_id: []const u8 = "",
    cve_score: f64 = 0,
    severity: VulnerabilitySeverity = .none,
    description: []const u8 = "",
    affected_versions: []const u8 = "",
    fix_version: []const u8 = "",
    known_exploitation: bool = false,
};

pub const DependencyInfo = struct {
    name: []const u8,
    version: []const u8 = "",
    dep_type: DependencyType,
    path: []const u8 = "",
    is_optional: bool = false,
    is_outdated: bool = false,
    is_vulnerable: bool = false,
    latest_version: []const u8 = "",
    vulnerabilities: []VulnerabilityInfo,
    has_valid_signature: bool = false,
    hash: [32]u8,
    file_size: u64 = 0,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        for (self.vulnerabilities) |*vuln| {
            if (vuln.description.len > 0) allocator.free(vuln.description);
        }
        allocator.free(self.vulnerabilities);
    }
};

pub const LicenseInfo = struct {
    name: []const u8 = "",
    spdx_id: []const u8 = "",
    is_osi_approved: bool = false,
    is_copyleft: bool = false,
    is_commercial: bool = false,
    risk_level: u8 = 0,
};

pub const DependencyFinding = struct {
    dependency_name: []const u8,
    issue_type: DependencyIssueType,
    severity: u8,
    cve_id: []const u8 = "",
    description: []const u8 = "",
    recommendation: []const u8 = "",
};

pub const DependencyIssueType = enum {
    known_vulnerability,
    outdated_version,
    deprecated_package,
    unsigned_dependency,
    removed_package,
    license_violation,
    abandoned_package,
    duplicate_dependency,
    insecure_protocol,
    untrusted_source,
};

pub const DependencyAnalysis = struct {
    dependencies: []DependencyInfo,
    findings: []DependencyFinding,
    licenses: []LicenseInfo,
    vulnerable_count: usize,
    outdated_count: usize,
    unsigned_count: usize,
    total_dependencies: usize,
    supply_chain_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        for (self.dependencies) |*d| d.deinit(allocator);
        allocator.free(self.dependencies);
        allocator.free(self.findings);
        allocator.free(self.licenses);
    }
};

const known_vulnerable_versions = [_]struct { name: []const u8, version: []const u8, cve: []const u8, score: f64 }{
    .{ .name = "libssl", .version = "1.0.1", .cve = "CVE-2014-0160", .score = 9.1 },
    .{ .name = "libssl", .version = "1.0.2", .cve = "CVE-2016-0800", .score = 7.5 },
    .{ .name = "libcurl", .version = "7.50", .cve = "CVE-2016-0755", .score = 6.8 },
    .{ .name = "zlib", .version = "1.2.8", .cve = "CVE-2016-9840", .score = 5.6 },
    .{ .name = "libpng", .version = "1.6.26", .cve = "CVE-2016-10087", .score = 7.8 },
    .{ .name = "libjpeg", .version = "9b", .cve = "CVE-2016-10143", .score = 6.5 },
    .{ .name = "openssl", .version = "1.1.0", .cve = "CVE-2018-0735", .score = 5.9 },
    .{ .name = "openssl", .version = "1.1.1", .cve = "CVE-2022-3602", .score = 8.1 },
    .{ .name = "libssh2", .version = "1.9.0", .cve = "CVE-2020-22219", .score = 7.5 },
    .{ .name = "sqlite3", .version = "3.36.0", .cve = "CVE-2022-35737", .score = 7.5 },
    .{ .name = "log4j", .version = "2.0", .cve = "CVE-2021-44228", .score = 10.0 },
    .{ .name = "log4j", .version = "2.17", .cve = "CVE-2021-44832", .score = 6.6 },
    .{ .name = "log4j", .version = "2.0", .cve = "CVE-2021-45105", .score = 5.9 },
    .{ .name = "spring", .version = "5.3.17", .cve = "CVE-2022-22965", .score = 9.8 },
    .{ .name = "spring", .version = "5.3.13", .cve = "CVE-2022-22963", .score = 7.5 },
    .{ .name = "libxml2", .version = "2.9.10", .cve = "CVE-2022-23308", .score = 7.5 },
    .{ .name = "expat", .version = "2.4.8", .cve = "CVE-2022-40674", .score = 7.5 },
    .{ .name = "openssl", .version = "3.0.0", .cve = "CVE-2022-3786", .score = 7.5 },
    .{ .name = "openssl", .version = "3.0.6", .cve = "CVE-2022-33521", .score = 5.3 },
    .{ .name = "curl", .version = "7.83", .cve = "CVE-2022-35252", .score = 5.3 },
    .{ .name = "curl", .version = "7.86", .cve = "CVE-2022-42915", .score = 7.5 },
    .{ .name = "pcre2", .version = "10.40", .cve = "CVE-2022-41409", .score = 5.5 },
    .{ .name = "zlib", .version = "1.2.12", .cve = "CVE-2022-37434", .score = 9.8 },
    .{ .name = "bzip2", .version = "1.0.6", .cve = "CVE-2016-3189", .score = 7.5 },
    .{ .name = "gzip", .version = "1.10", .cve = "CVE-2022-1271", .score = 5.5 },
    .{ .name = "libffi", .version = "3.4.2", .cve = "CVE-2021-35641", .score = 5.5 },
    .{ .name = "glibc", .version = "2.35", .cve = "CVE-2022-23218", .score = 5.5 },
    .{ .name = "glibc", .version = "2.34", .cve = "CVE-2021-3998", .score = 4.4 },
    .{ .name = "icu4c", .version = "71.1", .cve = "CVE-2022-3172", .score = 7.5 },
};

fn detectDependencyType(name: []const u8) DependencyType {
    if (utils.containsAny(name, &.{ ".so", ".dylib", ".dll" })) return .shared_library;
    if (utils.containsAny(name, &.{ ".a", ".lib" })) return .static_library;
    if (utils.containsAny(name, &.{ ".framework" })) return .framework;
    if (utils.containsAny(name, &.{ ".jar", ".war", ".ear" })) return .jar_archive;
    if (utils.containsAny(name, &.{ "python", ".py", "pip" })) return .python_package;
    if (utils.containsAny(name, &.{ "node", "npm", "package" })) return .npm_package;
    if (utils.containsAny(name, &.{ "nuget", ".nupkg" })) return .nuget_package;
    if (utils.containsAny(name, &.{ "cargo", "crate" })) return .cargo_crate;
    return .unknown;
}

pub fn analyzeDependencies(allocator: Allocator, _: []const u8, image: BinaryImage) !DependencyAnalysis {
    var dependencies = std.ArrayList(DependencyInfo).init(allocator);
    errdefer {
        for (dependencies.items) |*d| d.deinit(allocator);
        dependencies.deinit();
    }
    var findings = std.ArrayList(DependencyFinding).init(allocator);
    errdefer findings.deinit();
    var licenses = std.ArrayList(LicenseInfo).init(allocator);
    errdefer licenses.deinit();

    for (image.imports) |import| {
        const dll = import.dll;
        if (dll.len == 0) continue;

        const exists = for (dependencies.items) |existing| {
            if (utils.asciiEqlIgnoreCase(existing.name, dll)) break true;
        } else false;
        if (exists) continue;

        const hash: [32]u8 = undefined;
        var d: DependencyInfo = .{
            .name = dll,
            .version = "",
            .dep_type = detectDependencyType(dll),
            .path = dll,
            .is_optional = false,
            .is_outdated = false,
            .is_vulnerable = false,
            .latest_version = "",
            .vulnerabilities = try allocator.alloc(VulnerabilityInfo, 0),
            .has_valid_signature = false,
            .hash = hash,
            .file_size = 0,
        };

        try checkVulnerabilities(dll, &d, &findings, allocator);
        try checkLicense(dll, &licenses, allocator);
        try dependencies.append(d);
    }

    for (image.symbols) |sym| {
        if (sym.external) {
            const hash: [32]u8 = undefined;
            var d: DependencyInfo = .{
                .name = sym.name,
                .version = "",
                .dep_type = .unknown,
                .path = "",
                .is_optional = false,
                .is_outdated = false,
                .is_vulnerable = false,
                .latest_version = "",
                .vulnerabilities = try allocator.alloc(VulnerabilityInfo, 0),
                .has_valid_signature = false,
                .hash = hash,
                .file_size = 0,
            };
            const exists = for (dependencies.items) |existing| {
                if (utils.asciiEqlIgnoreCase(existing.name, sym.name)) break true;
            } else false;
            if (!exists) {
                try checkVulnerabilities(sym.name, &d, &findings, allocator);
                try dependencies.append(d);
            } else {
                d.deinit(allocator);
            }
        }
    }

    var vulnerable: usize = 0;
    var outdated: usize = 0;
    var unsigned_deps: usize = 0;

    for (dependencies.items) |dep| {
        if (dep.is_vulnerable) vulnerable += 1;
        if (dep.is_outdated) outdated += 1;
        if (!dep.has_valid_signature) unsigned_deps += 1;
    }

    var score: f64 = 100.0;
    if (dependencies.items.len > 0) {
        score -= @as(f64, @floatFromInt(vulnerable)) * 25.0 / @as(f64, @floatFromInt(dependencies.items.len));
        score -= @as(f64, @floatFromInt(unsigned_deps)) * 10.0 / @as(f64, @floatFromInt(dependencies.items.len));
    }

    const total_deps = dependencies.items.len;
    return .{
        .dependencies = try dependencies.toOwnedSlice(),
        .findings = try findings.toOwnedSlice(),
        .licenses = try licenses.toOwnedSlice(),
        .vulnerable_count = vulnerable,
        .outdated_count = outdated,
        .unsigned_count = unsigned_deps,
        .total_dependencies = total_deps,
        .supply_chain_score = utils.clamp100(score),
    };
}

fn extractVersionTag(name: []const u8) ?[]const u8 {
    if (std.mem.lastIndexOfScalar(u8, name, '@')) |at_pos| {
        const tag = name[at_pos + 1 ..];
        for (tag, 0..) |c, i| {
            if (std.ascii.isDigit(c)) return tag[i..];
        }
    }
    return null;
}

fn compareVersions(a: []const u8, b: []const u8) std.math.Order {
    var it_a = std.mem.splitScalar(u8, a, '.');
    var it_b = std.mem.splitScalar(u8, b, '.');
    while (true) {
        const part_a = it_a.next();
        const part_b = it_b.next();
        if (part_a == null and part_b == null) return .eq;
        if (part_a == null) return .lt;
        if (part_b == null) return .gt;
        const va = std.fmt.parseInt(u64, part_a.?, 10) catch return .eq;
        const vb = std.fmt.parseInt(u64, part_b.?, 10) catch return .eq;
        if (va < vb) return .lt;
        if (va > vb) return .gt;
    }
}

fn checkVulnerabilities(name: []const u8, dep: *DependencyInfo, findings: *std.ArrayList(DependencyFinding), allocator: Allocator) !void {
    var vuln_list = std.ArrayList(VulnerabilityInfo).init(allocator);
    defer vuln_list.deinit();
    var any_match = false;
    const extracted_version = extractVersionTag(name);

    for (known_vulnerable_versions) |known| {
        if (!utils.asciiContainsIgnoreCase(name, known.name)) continue;

        const version_is_known = extracted_version != null;
        const version_matches = if (extracted_version) |ver|
            compareVersions(ver, known.version) == .eq
        else
            false;

        if (version_is_known and !version_matches) continue;

        const confirmed = version_matches;
        any_match = true;

        const vuln_description = if (confirmed)
            try std.fmt.allocPrint(allocator, "Known vulnerability in {s} (version {s} matches known affected version {s})", .{ known.name, extracted_version.?, known.version })
        else
            try std.fmt.allocPrint(allocator, "Possible vulnerability in {s} — version not confirmed (known affected version: {s})", .{ known.name, known.version });

        try vuln_list.append(.{
            .cve_id = known.cve,
            .cve_score = if (confirmed) known.score else known.score * 0.5,
            .severity = if (confirmed)
                (if (known.score >= 9.0) .critical else if (known.score >= 7.0) .high else if (known.score >= 4.0) .medium else .low)
            else
                .low,
            .description = vuln_description,
            .affected_versions = known.version,
            .fix_version = "",
            .known_exploitation = confirmed and known.score >= 8.0,
        });

        const finding_desc = if (confirmed)
            "Known vulnerability (confirmed version match)"
        else
            "Possible vulnerability — version not confirmed";
        try findings.append(.{
            .dependency_name = dep.name,
            .issue_type = .known_vulnerability,
            .severity = if (confirmed)
                (if (known.score >= 9.0) @as(u8, 95) else if (known.score >= 7.0) @as(u8, 80) else @as(u8, 50))
            else
                30,
            .cve_id = known.cve,
            .description = finding_desc,
            .recommendation = "Update to patched version",
        });
    }

    if (any_match) {
        dep.is_vulnerable = true;
        if (extracted_version) |ver| dep.version = ver;
        dep.deinit(allocator);
        dep.vulnerabilities = try vuln_list.toOwnedSlice();
    }
}

fn checkLicense(name: []const u8, licenses: *std.ArrayList(LicenseInfo), allocator: Allocator) !void {
    _ = allocator;
    if (utils.containsAny(name, &.{ "gpl", "GPL", "lgpl", "LGPL" })) {
        try licenses.append(.{
            .name = "GNU General Public License",
            .spdx_id = "GPL-3.0-only",
            .is_osi_approved = true,
            .is_copyleft = true,
            .is_commercial = false,
            .risk_level = 40,
        });
    } else if (utils.containsAny(name, &.{ "MIT", "mit" })) {
        try licenses.append(.{
            .name = "MIT License",
            .spdx_id = "MIT",
            .is_osi_approved = true,
            .is_copyleft = false,
            .is_commercial = false,
            .risk_level = 5,
        });
    } else if (utils.containsAny(name, &.{ "apache", "Apache" })) {
        try licenses.append(.{
            .name = "Apache License 2.0",
            .spdx_id = "Apache-2.0",
            .is_osi_approved = true,
            .is_copyleft = false,
            .is_commercial = false,
            .risk_level = 10,
        });
    } else if (utils.containsAny(name, &.{ "BSD", "bsd" })) {
        try licenses.append(.{
            .name = "BSD License",
            .spdx_id = "BSD-3-Clause",
            .is_osi_approved = true,
            .is_copyleft = false,
            .is_commercial = false,
            .risk_level = 5,
        });
    }
}

pub fn detectSupplyChainRisks(allocator: Allocator, _: []const u8, image: BinaryImage) ![]DependencyFinding {
    var findings = std.ArrayList(DependencyFinding).init(allocator);
    errdefer findings.deinit();

    const high_risk_libs = [_][]const u8{
        "libcurl", "openssl", "libssh", "libssl", "libcrypto",
        "zlib", "libpng", "libjpeg", "libxml2", "expat",
    };

    for (image.imports) |import| {
        for (high_risk_libs) |risk_lib| {
            if (utils.asciiContainsIgnoreCase(import.name, risk_lib)) {
                try findings.append(.{
                    .dependency_name = import.name,
                    .issue_type = .insecure_protocol,
                    .severity = 40,
                    .description = "High-risk dependency without pinned version or integrity check",
                    .recommendation = "Pin dependency to specific version and verify checksum",
                });
                break;
            }
        }
    }

    return findings.toOwnedSlice();
}

pub fn findEmbeddedLibraries(bytes: []const u8) ![]DependencyInfo {
    _ = bytes;
    return error.NotImplemented;
}
