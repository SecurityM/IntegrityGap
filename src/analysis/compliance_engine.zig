const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const decoder = @import("../core/decoder.zig");
const crypto_auditor = @import("crypto_auditor.zig");
const privacy_analyzer = @import("privacy_analyzer.zig");

const Allocator = types.Allocator;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const FunctionSpan = types.FunctionSpan;

pub const RegulatoryFramework = enum {
    pci_dss,
    hipaa,
    soc2,
    iso_27001,
    fedramp,
    nist_800_53,
    nist_800_171,
    cis_controls,
    gdpr_technical,
    custom,
};

pub const ComplianceRequirement = struct {
    framework: RegulatoryFramework,
    requirement_id: []const u8,
    title: []const u8,
    description: []const u8,
    severity: u8,
    automated_check: bool,
    category: ComplianceCategory,
};

pub const ComplianceCategory = enum {
    access_control,
    encryption,
    logging_monitoring,
    vulnerability_management,
    configuration_management,
    incident_response,
    data_protection,
    network_security,
    physical_security,
    asset_management,
    third_party_risk,
    business_continuity,
};

pub const Confidence = enum {
    confirmed,
    likely,
    heuristic,
    unknown,
};

pub const ComplianceFinding = struct {
    requirement: ComplianceRequirement,
    status: ComplianceStatus,
    confidence: Confidence = .unknown,
    evidence: []const u8 = "",
    recommendation: []const u8 = "",
    function_va: u64 = 0,
    address: u64 = 0,
};

pub const ComplianceStatus = enum {
    compliant,
    non_compliant,
    not_applicable,
    not_checked,
    partial,
};

pub const ComplianceReport = struct {
    framework: RegulatoryFramework,
    total_checks: usize,
    passed: usize,
    failed: usize,
    not_applicable: usize,
    not_checked: usize,
    partial: usize,
    score: f64,
    findings: []ComplianceFinding,
    requirements: []ComplianceRequirement,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.findings);
        allocator.free(self.requirements);
    }
};

pub const ComplianceSuite = struct {
    reports: []ComplianceReport,
    overall_score: f64,
    critical_findings: usize,
    high_findings: usize,
    medium_findings: usize,
    low_findings: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        for (self.reports) |*report| report.deinit(allocator);
        allocator.free(self.reports);
    }
};

const pci_dss_requirements = [_]ComplianceRequirement{
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-1.1",
        .title = "Install and maintain firewall configuration",
        .description = "Firewall configuration must restrict traffic between trusted and untrusted networks",
        .severity = 90,
        .automated_check = false,
        .category = .network_security,
    },
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-2.1",
        .title = "Change vendor defaults",
        .description = "Remove default accounts, passwords, and configurations",
        .severity = 85,
        .automated_check = true,
        .category = .configuration_management,
    },
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-3.1",
        .title = "Protect stored cardholder data",
        .description = "Encrypt stored cardholder data using strong cryptography",
        .severity = 95,
        .automated_check = true,
        .category = .data_protection,
    },
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-3.5",
        .title = "Protect encryption keys",
        .description = "Encryption keys must be stored securely, not in plaintext",
        .severity = 95,
        .automated_check = true,
        .category = .encryption,
    },
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-4.1",
        .title = "Encrypt transmission of cardholder data",
        .description = "Use strong cryptography for cardholder data over public networks",
        .severity = 95,
        .automated_check = true,
        .category = .encryption,
    },
    .{
        .framework = .pci_dss,
        .requirement_id = "PCI-10.1",
        .title = "Implement audit trails",
        .description = "Log access to cardholder data and system components",
        .severity = 80,
        .automated_check = true,
        .category = .logging_monitoring,
    },
};

const hipaa_requirements = [_]ComplianceRequirement{
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(a)(1)",
        .title = "Access control",
        .description = "Implement technical policies for access to ePHI",
        .severity = 85,
        .automated_check = true,
        .category = .access_control,
    },
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(a)(2)(iv)",
        .title = "Encryption and decryption",
        .description = "Encrypt ePHI at rest and in transit",
        .severity = 90,
        .automated_check = true,
        .category = .encryption,
    },
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(b)",
        .title = "Audit controls",
        .description = "Record and examine access to ePHI",
        .severity = 80,
        .automated_check = true,
        .category = .logging_monitoring,
    },
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(c)(1)",
        .title = "Integrity controls",
        .description = "Ensure ePHI not improperly altered or destroyed",
        .severity = 85,
        .automated_check = true,
        .category = .data_protection,
    },
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(d)",
        .title = "Person or entity authentication",
        .description = "Verify persons accessing ePHI",
        .severity = 80,
        .automated_check = false,
        .category = .access_control,
    },
    .{
        .framework = .hipaa,
        .requirement_id = "HIPAA-164.312(e)(1)",
        .title = "Transmission security",
        .description = "Guard against unauthorized access to ePHI transmitted over networks",
        .severity = 90,
        .automated_check = true,
        .category = .network_security,
    },
};

const soc2_requirements = [_]ComplianceRequirement{
    .{
        .framework = .soc2,
        .requirement_id = "SOC2-CC1.1",
        .title = "Control environment",
        .description = "Organizational commitment to integrity and ethical values",
        .severity = 70,
        .automated_check = false,
        .category = .access_control,
    },
    .{
        .framework = .soc2,
        .requirement_id = "SOC2-CC6.1",
        .title = "Logical and physical access controls",
        .description = "Restrict logical access to system components",
        .severity = 80,
        .automated_check = true,
        .category = .access_control,
    },
    .{
        .framework = .soc2,
        .requirement_id = "SOC2-CC6.7",
        .title = "Data encryption",
        .description = "Protect data-in-transit and data-at-rest",
        .severity = 85,
        .automated_check = true,
        .category = .encryption,
    },
    .{
        .framework = .soc2,
        .requirement_id = "SOC2-CC7.2",
        .title = "Monitoring controls",
        .description = "Detect and respond to security events",
        .severity = 75,
        .automated_check = true,
        .category = .logging_monitoring,
    },
    .{
        .framework = .soc2,
        .requirement_id = "SOC2-A1.2",
        .title = "Availability monitoring",
        .description = "Monitor capacity and performance for availability commitments",
        .severity = 65,
        .automated_check = false,
        .category = .business_continuity,
    },
};

const iso_27001_requirements = [_]ComplianceRequirement{
    .{
        .framework = .iso_27001,
        .requirement_id = "ISO-A.9.1.2",
        .title = "Access to networks and network services",
        .description = "Users should only have access to specific networks and services",
        .severity = 75,
        .automated_check = true,
        .category = .access_control,
    },
    .{
        .framework = .iso_27001,
        .requirement_id = "ISO-A.10.1.1",
        .title = "Cryptographic controls",
        .description = "Policy for use of cryptographic controls",
        .severity = 80,
        .automated_check = true,
        .category = .encryption,
    },
    .{
        .framework = .iso_27001,
        .requirement_id = "ISO-A.12.4.1",
        .title = "Event logging",
        .description = "Event logs recording user activities, exceptions, and faults",
        .severity = 75,
        .automated_check = true,
        .category = .logging_monitoring,
    },
    .{
        .framework = .iso_27001,
        .requirement_id = "ISO-A.12.6.1",
        .title = "Management of technical vulnerabilities",
        .description = "Timely information about technical vulnerabilities",
        .severity = 80,
        .automated_check = true,
        .category = .vulnerability_management,
    },
};

pub fn loadFrameworkRequirements(framework: RegulatoryFramework, allocator: Allocator) ![]ComplianceRequirement {
    const slice = switch (framework) {
        .pci_dss => &pci_dss_requirements,
        .hipaa => &hipaa_requirements,
        .soc2 => &soc2_requirements,
        .iso_27001 => &iso_27001_requirements,
        .nist_800_53, .nist_800_171, .fedramp, .cis_controls, .gdpr_technical, .custom => return error.FrameworkNotImplemented,
    };

    const copied = try allocator.alloc(ComplianceRequirement, slice.len);
    for (copied, slice[0..]) |*dest, src| dest.* = src;
    return copied;
}

fn isStripped(image: BinaryImage) bool {
    for (image.symbols) |sym| {
        if (sym.is_function and !sym.external) return false;
    }
    return true;
}

fn heuristicCheck(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan, patterns: []const []const u8) ?bool {
    var found: bool = false;
    for (functions) |fn_span| {
        const func_instrs = instrs[fn_span.instr_start..fn_span.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                if (utils.containsAny(resolved.name, patterns)) {
                    found = true;
                }
            }
        }
    }
    if (!found and isStripped(image)) return null;
    return found;
}

fn checkEncryptionRequirement(_: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ?bool {
    return heuristicCheck(instrs, image, functions, &.{ "Encrypt", "encrypt", "AES", "GCM", "CBC", "CryptEncrypt", "BCryptEncrypt" });
}

fn checkLoggingRequirement(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ?bool {
    return heuristicCheck(instrs, image, functions, &.{ "log", "syslog", "event", "audit", "trail" });
}

fn checkAccessControlMechanism(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ?bool {
    return heuristicCheck(instrs, image, functions, &.{ "authenticate", "login", "authorize", "permission", "access_check", "verify_identity" });
}

pub fn runComplianceCheck(allocator: Allocator, framework: RegulatoryFramework, bytes: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !ComplianceReport {
    const requirements = try loadFrameworkRequirements(framework, allocator);
    errdefer allocator.free(requirements);

    var findings = std.ArrayList(ComplianceFinding).init(allocator);
    errdefer findings.deinit();

    var passed: usize = 0;
    var failed: usize = 0;
    var na: usize = 0;
    var not_checked: usize = 0;
    var partial: usize = 0;

    for (requirements) |req| {
        var conf: Confidence = .unknown;
        const status = try evaluateRequirement(req, allocator, bytes, instrs, image, functions, &conf);
        try findings.append(.{
            .requirement = req,
            .status = status,
            .confidence = conf,
            .evidence = "",
            .recommendation = getRecommendation(req, status),
        });

        switch (status) {
            .compliant => passed += 1,
            .non_compliant => failed += 1,
            .not_applicable => na += 1,
            .not_checked => not_checked += 1,
            .partial => partial += 1,
        }
    }

    const score = if (passed + failed + partial == 0) 100.0 else
        @as(f64, @floatFromInt(passed)) * 100.0 / @as(f64, @floatFromInt(passed + failed + partial));

    return .{
        .framework = framework,
        .total_checks = requirements.len,
        .passed = passed,
        .failed = failed,
        .not_applicable = na,
        .not_checked = not_checked,
        .partial = partial,
        .score = score,
        .findings = try findings.toOwnedSlice(),
        .requirements = requirements,
    };
}

fn evaluateRequirement(req: ComplianceRequirement, _: Allocator, bytes: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan, confidence: *Confidence) !ComplianceStatus {
    if (!req.automated_check) return .not_checked;
    confidence.* = .heuristic;

    const result: ?bool = switch (req.category) {
        .encryption => checkEncryptionRequirement(bytes, instrs, image, functions),
        .logging_monitoring => checkLoggingRequirement(instrs, image, functions),
        .access_control => checkAccessControlMechanism(instrs, image, functions),
        .data_protection => checkEncryptionRequirement(bytes, instrs, image, functions),
        .network_security => checkNetworkSecurity(instrs, image, functions),
        .configuration_management => checkConfigurationManagement(instrs, image, functions),
        .vulnerability_management => null,
        else => return .not_checked,
    };

    if (result) |found| {
        if (found) {
            confidence.* = .likely;
            return .compliant;
        }
        return .non_compliant;
    }
    confidence.* = .unknown;
    return .partial;
}

fn checkNetworkSecurity(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ?bool {
    return heuristicCheck(instrs, image, functions, &.{ "TLS", "SSL", "https", "secure_", "certificate", "verify_cert" });
}

fn checkConfigurationManagement(instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) ?bool {
    return heuristicCheck(instrs, image, functions, &.{ "config", "setting", "option", "parameter", "default" });
}

fn getRecommendation(req: ComplianceRequirement, status: ComplianceStatus) []const u8 {
    if (status == .compliant) return "Possible evidence of compliance detected via heuristic analysis — verify manually";
    return switch (req.category) {
        .encryption => "Implement strong encryption (AES-256-GCM or ChaCha20-Poly1305) for data protection",
        .logging_monitoring => "Implement comprehensive audit logging covering all security events",
        .access_control => "Implement role-based access control with strong authentication",
        .data_protection => "Implement data encryption at rest and in transit with key management",
        .network_security => "Implement TLS 1.2+ with certificate validation for all network communications",
        .configuration_management => "Review and harden default configurations, remove default credentials",
        .vulnerability_management => "Establish vulnerability scanning and patch management process",
        else => "Review and address compliance requirements",
    };
}

pub fn runFullComplianceSuite(allocator: Allocator, bytes: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !ComplianceSuite {
    const frameworks = [_]RegulatoryFramework{ .pci_dss, .hipaa, .soc2, .iso_27001 };
    var reports = std.ArrayList(ComplianceReport).init(allocator);
    errdefer {
        for (reports.items) |*r| r.deinit(allocator);
        reports.deinit();
    }

    var total_critical: usize = 0;
    var total_high: usize = 0;
    var total_medium: usize = 0;
    var total_low: usize = 0;

    for (frameworks) |fw| {
        const report = try runComplianceCheck(allocator, fw, bytes, instrs, image, functions);
        for (report.findings) |f| {
            if (f.status == .non_compliant) {
                if (f.requirement.severity >= 90) {
                    total_critical += 1;
                } else if (f.requirement.severity >= 75) {
                    total_high += 1;
                } else if (f.requirement.severity >= 50) {
                    total_medium += 1;
                } else {
                    total_low += 1;
                }
            }
        }
        try reports.append(report);
    }

    var total_score: f64 = 0;
    for (reports.items) |r| total_score += r.score;
    const overall = if (reports.items.len > 0) total_score / @as(f64, @floatFromInt(reports.items.len)) else 0;

    return .{
        .reports = try reports.toOwnedSlice(),
        .overall_score = overall,
        .critical_findings = total_critical,
        .high_findings = total_high,
        .medium_findings = total_medium,
        .low_findings = total_low,
    };
}
