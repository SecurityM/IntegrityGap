const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const crypto_auditor = @import("../analysis/crypto_auditor.zig");
const compliance_engine = @import("../analysis/compliance_engine.zig");
const concurrency_analyzer = @import("../analysis/concurrency_analyzer.zig");
const taint_analyzer = @import("../analysis/taint_analyzer.zig");
const firmware_integrity = @import("../analysis/firmware_integrity.zig");
const privacy_analyzer = @import("../analysis/privacy_analyzer.zig");
const memory_safety = @import("../analysis/memory_safety.zig");
const dependency_checker = @import("../analysis/dependency_checker.zig");
const config_auditor = @import("../analysis/config_auditor.zig");

const Allocator = types.Allocator;

pub const ReportFormat = enum {
    html,
    markdown,
    json_verbose,
    csv,
    sarif,
    pdf_compatible,
    junit_xml,
};

pub const ReportSectionType = enum {
    executive_summary,
    target_information,
    concurrency_analysis,
    taint_analysis,
    firmware_integrity,
    crypto_audit,
    privacy_analysis,
    compliance_check,
    memory_safety,
    dependency_scan,
    config_audit,
    integrity_gap_analysis,
    call_graph,
    evidence,
    recommendations,
    appendix,
};

pub const ReportSection = struct {
    section_type: ReportSectionType,
    title: []const u8,
    content: []const u8,
    severity_score: f64 = 0,
    finding_count: usize = 0,
};

pub const Report = struct {
    title: []const u8,
    version: []const u8 = "2.1.0",
    timestamp: i64,
    target_path: []const u8,
    sha256: [32]u8,
    format: ReportFormat,
    sections: []ReportSection,
    overall_score: f64,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    total_findings: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.sections);
    }
};

pub fn generateComprehensiveReport(
    allocator: Allocator,
    target_path: []const u8,
    sha256: [32]u8,
    format: ReportFormat,
    integrity_analysis: ?*const types.Analysis,
    concurrency: ?*const concurrency_analyzer.ConcurrencyAnalysis,
    taint: ?*const taint_analyzer.TaintAnalysis,
    firmware: ?*const firmware_integrity.FirmwareAnalysis,
    crypto: ?*const crypto_auditor.CryptoAudit,
    privacy: ?*const privacy_analyzer.PrivacyAnalysis,
    compliance: ?*const compliance_engine.ComplianceSuite,
    memory: ?*const memory_safety.BinarySafetyAnalysis,
    dependencies: ?*const dependency_checker.DependencyAnalysis,
    config: ?*const config_auditor.ConfigAudit,
) !Report {
    var sections = std.ArrayList(ReportSection).init(allocator);
    errdefer sections.deinit();
    var scores = std.ArrayList(f64).init(allocator);
    defer scores.deinit();

    var total_critical: usize = 0;
    var total_high: usize = 0;
    var total_medium: usize = 0;
    var total_low: usize = 0;

    try addExecutiveSummary(&sections, &scores, integrity_analysis, &total_critical, &total_high, &total_medium, &total_low, allocator);

    if (integrity_analysis) |ia| {
        try addIntegrityGapSection(&sections, ia, allocator);
    }

    if (concurrency) |c| {
        try addConcurrencySection(&sections, c, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(c.concurrency_gap_score);
    }

    if (taint) |t| {
        try addTaintSection(&sections, t, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(t.taint_gap_score);
    }

    if (firmware) |f| {
        try addFirmwareSection(&sections, f, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(f.integrity_score);
    }

    if (crypto) |cr| {
        try addCryptoSection(&sections, cr, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(cr.crypto_gap_score);
    }

    if (privacy) |pr| {
        try addPrivacySection(&sections, pr, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(pr.privacy_gap_score);
    }

    if (compliance) |co| {
        try addComplianceSection(&sections, co, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(co.overall_score);
    }

    if (memory) |m| {
        try addMemorySection(&sections, m, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(m.safety_gap_score);
    }

    if (dependencies) |d| {
        try addDependencySection(&sections, d, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(d.supply_chain_score);
    }

    if (config) |cf| {
        try addConfigSection(&sections, cf, &total_critical, &total_high, &total_medium, &total_low, allocator);
        try scores.append(cf.config_security_score);
    }

    try addRecommendations(&sections, allocator);
    try addAppendix(&sections, allocator);

    var overall: f64 = 0;
    for (scores.items) |s| overall += s;
    if (scores.items.len > 0) overall /= @as(f64, @floatFromInt(scores.items.len));

    return .{
        .title = "IntegrityGap Comprehensive Security Report",
        .version = "2.1.0",
        .timestamp = std.time.timestamp(),
        .target_path = target_path,
        .sha256 = sha256,
        .format = format,
        .sections = try sections.toOwnedSlice(),
        .overall_score = overall,
        .critical_count = total_critical,
        .high_count = total_high,
        .medium_count = total_medium,
        .low_count = total_low,
        .total_findings = total_critical + total_high + total_medium + total_low,
    };
}

fn addExecutiveSummary(sections: *std.ArrayList(ReportSection), scores: *std.ArrayList(f64), analysis: ?*const types.Analysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    _ = scores;
    const threat_str = if (analysis) |a| @tagName(a.summary.threat) else "N/A";
    const gap_str = if (analysis) |a| try std.fmt.allocPrint(allocator, "{d:.2}", .{a.summary.aggregate_gap}) else "N/A";
    const confidence_str = if (analysis) |a| try std.fmt.allocPrint(allocator, "{d:.2}", .{a.summary.anomaly_confidence}) else "N/A";
    const findings_count = if (analysis) |a| a.evidence.len else 0;
    _ = findings_count;

    critical.* += if (analysis) |a| countSeverity(a.evidence, 90, 100) else 0;
    high.* += if (analysis) |a| countSeverity(a.evidence, 70, 89) else 0;
    medium.* += if (analysis) |a| countSeverity(a.evidence, 40, 69) else 0;
    low.* += if (analysis) |a| countSeverity(a.evidence, 1, 39) else 0;

    const content = try std.fmt.allocPrint(allocator,
        \\# Executive Summary
        \\
        \\**Target:** {s}
        \\**Threat Classification:** {s}
        \\**Aggregate Gap Score:** {s}
        \\**Anomaly Confidence:** {s}
        \\
        \\This report provides a comprehensive security analysis including integrity gaps,
        \\concurrency issues, taint propagation, firmware integrity, cryptographic auditing,
        \\privacy compliance, regulatory compliance, memory safety, dependency scanning,
        \\and configuration auditing.
        \\
    , .{ if (analysis) |a| a.target_path else "unknown", threat_str, gap_str, confidence_str });

    try sections.append(.{
        .section_type = .executive_summary,
        .title = "Executive Summary",
        .content = content,
        .severity_score = if (analysis) |a| a.summary.aggregate_gap else 0,
        .finding_count = if (analysis) |a| a.evidence.len else 0,
    });
}

fn addIntegrityGapSection(sections: *std.ArrayList(ReportSection), analysis: *const types.Analysis, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Integrity Gap Analysis\n\n", .{});
    try w.print("- Format: {s}\n", .{@tagName(analysis.image.format)});
    try w.print("- Architecture: {s}\n", .{@tagName(analysis.image.arch)});
    try w.print("- Entry Point: 0x{x}\n", .{analysis.image.entry_va});
    try w.print("- Executable Sections: {}\n", .{parser_countExecSections(analysis.image)});
    try w.print("- Functions Identified: {}\n", .{analysis.functions.len});
    try w.print("- Instructions Decoded: {}\n", .{analysis.instructions.len});
    try w.print("- Evidence Found: {}\n", .{analysis.evidence.len});
    try w.print("- Threat Class: {s}\n", .{@tagName(analysis.summary.threat)});
    try w.print("- Anomaly Confidence: {d:.2}%\n", .{analysis.summary.anomaly_confidence});
    try w.print("- Aggregate Gap: {d:.2}\n\n", .{analysis.summary.aggregate_gap});

    try w.writeAll("### Category Scores\n\n");
    try w.print("- Error Handling: {d:.2}\n", .{analysis.summary.scores.error_handling});
    try w.print("- Resource Lifecycle: {d:.2}\n", .{analysis.summary.scores.resource_lifecycle});
    try w.print("- Input Validation: {d:.2}\n", .{analysis.summary.scores.input_validation});
    try w.print("- Cryptographic: {d:.2}\n", .{analysis.summary.scores.cryptographic});
    try w.print("- Logging/Auditability: {d:.2}\n", .{analysis.summary.scores.logging_auditability});
    try w.print("- Cleanup: {d:.2}\n", .{analysis.summary.scores.cleanup});

    try sections.append(.{
        .section_type = .integrity_gap_analysis,
        .title = "Integrity Gap Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = analysis.summary.aggregate_gap,
        .finding_count = analysis.evidence.len,
    });
}

fn addConcurrencySection(sections: *std.ArrayList(ReportSection), concurrency: *const concurrency_analyzer.ConcurrencyAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Concurrency Analysis\n\n", .{});
    try w.print("- Race Conditions Detected: {}\n", .{concurrency.race_conditions.len});
    try w.print("- Threading Issues: {}\n", .{concurrency.threading_issues.len});
    try w.print("- Unguarded Shared Data: {} / {}\n", .{ concurrency.unguarded_shared_data, concurrency.total_shared_locations });
    try w.print("- Deadlock Potential: {d:.2}%\n", .{concurrency.deadlock_potential});
    try w.print("- Concurrency Gap Score: {d:.2}\n\n", .{concurrency.concurrency_gap_score});

    if (concurrency.race_conditions.len > 0) {
        try w.writeAll("### Race Conditions\n\n");
        for (concurrency.race_conditions, 0..) |race, idx| {
            if (idx >= 10) {
                try w.print("- ... and {} more\n", .{concurrency.race_conditions.len - 10});
                break;
            }
            try w.print("- Address 0x{x}: {s}\n", .{ race.address, race.description });
        }
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .concurrency_analysis,
        .title = "Concurrency Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = concurrency.concurrency_gap_score,
        .finding_count = concurrency.race_conditions.len + concurrency.threading_issues.len,
    });
}

fn addTaintSection(sections: *std.ArrayList(ReportSection), taint: *const taint_analyzer.TaintAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Taint Analysis\n\n", .{});
    try w.print("- Taint Sources Found: {}\n", .{taint.sources.len});
    try w.print("- Taint Sinks Found: {}\n", .{taint.sinks.len});
    try w.print("- Unvalidated Paths: {} / {}\n", .{ taint.unvalidated_paths, taint.total_paths });
    try w.print("- Critical Severity Paths: {}\n", .{taint.critical_severity_count});
    try w.print("- High Severity Paths: {}\n", .{taint.high_severity_count});
    try w.print("- Taint Gap Score: {d:.2}\n\n", .{taint.taint_gap_score});

    for (taint.propagations) |prop| {
        try w.print("- [{s}] {s} -> {s} (severity: {s})\n", .{
            @tagName(prop.source_type), @tagName(prop.sink_type),
            @tagName(prop.severity), prop.description,
        });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .taint_analysis,
        .title = "Taint Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = taint.taint_gap_score,
        .finding_count = taint.propagations.len,
    });
}

fn addFirmwareSection(sections: *std.ArrayList(ReportSection), firmware: *const firmware_integrity.FirmwareAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Firmware Integrity Analysis\n\n", .{});
    try w.print("- Format: {s}\n", .{@tagName(firmware.format)});
    try w.print("- Total Size: {} bytes\n", .{firmware.total_size});
    try w.print("- Regions Identified: {}\n", .{firmware.regions.len});
    try w.print("- Integrity Violations: {}\n", .{firmware.findings.len});
    try w.print("- Integrity Score: {d:.2}%\n", .{firmware.integrity_score});
    try w.print("- Boot Chain Trusted: {}\n", .{firmware.boot_chain_trusted});
    try w.print("- Has Rollback Protection: {}\n", .{firmware.has_rollback_protection});
    try w.print("- Has Secure Boot: {}\n", .{firmware.has_secure_boot});
    try w.print("- Immutable Regions: {}\n\n", .{firmware.immutable_region_count});

    for (firmware.findings) |finding| {
        try w.print("- [severity={}] {s}\n", .{ finding.severity, finding.description });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .firmware_integrity,
        .title = "Firmware Integrity Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = firmware.integrity_score,
        .finding_count = firmware.findings.len,
    });
}

fn addCryptoSection(sections: *std.ArrayList(ReportSection), crypto: *const crypto_auditor.CryptoAudit, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Cryptographic Audit\n\n", .{});
    try w.print("- Cipher Usages: {}\n", .{crypto.cipher_usages.len});
    try w.print("- Weak Ciphers: {}\n", .{crypto.weak_cipher_count});
    try w.print("- Hardcoded Keys: {}\n", .{crypto.hardcoded_key_count});
    try w.print("- Deprecated Algorithms: {}\n", .{crypto.deprecated_count});
    try w.print("- Crypto Gap Score: {d:.2}\n\n", .{crypto.crypto_gap_score});

    for (crypto.findings) |f| {
        try w.print("- [severity={}] {s}\n", .{ f.severity, f.description });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .crypto_audit,
        .title = "Cryptographic Audit",
        .content = try content.toOwnedSlice(),
        .severity_score = crypto.crypto_gap_score,
        .finding_count = crypto.findings.len,
    });
}

fn addPrivacySection(sections: *std.ArrayList(ReportSection), privacy: *const privacy_analyzer.PrivacyAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Privacy Analysis\n\n", .{});
    try w.print("- Privacy Findings: {}\n", .{privacy.findings.len});
    try w.print("- PII Collection Points: {}\n", .{privacy.pii_collection_points});
    try w.print("- Data Sharing Operations: {}\n", .{privacy.data_share_operations});
    try w.print("- Consent Mechanisms: {}\n", .{privacy.consent_mechanisms});
    try w.print("- GDPR Compliance: {d:.2}%\n", .{privacy.gdpr_compliance_score});
    try w.print("- CCPA Compliance: {d:.2}%\n", .{privacy.ccpa_compliance_score});
    try w.print("- HIPAA Compliance: {d:.2}%\n", .{privacy.hipaa_compliance_score});
    try w.print("- Privacy Gap Score: {d:.2}\n\n", .{privacy.privacy_gap_score});

    for (privacy.findings) |f| {
        try w.print("- {s} (Art: {s})\n", .{ f.description, f.gdpr_articles });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .privacy_analysis,
        .title = "Privacy Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = privacy.privacy_gap_score,
        .finding_count = privacy.findings.len,
    });
}

fn addComplianceSection(sections: *std.ArrayList(ReportSection), compliance: *const compliance_engine.ComplianceSuite, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Compliance Assessment\n\n", .{});
    try w.print("- Overall Score: {d:.2}%\n", .{compliance.overall_score});
    try w.print("- Critical: {} | High: {} | Medium: {} | Low: {}\n\n", .{ compliance.critical_findings, compliance.high_findings, compliance.medium_findings, compliance.low_findings });

    for (compliance.reports) |report| {
        try w.print("### {s}\n", .{@tagName(report.framework)});
        try w.print("- Passed: {} | Failed: {} | N/A: {} | Not Checked: {}\n", .{ report.passed, report.failed, report.not_applicable, report.not_checked });
        try w.print("- Score: {d:.2}%\n\n", .{report.score});
    }

    critical.* += compliance.critical_findings;
    high.* += compliance.high_findings;
    medium.* += compliance.medium_findings;
    low.* += compliance.low_findings;

    try sections.append(.{
        .section_type = .compliance_check,
        .title = "Compliance Assessment",
        .content = try content.toOwnedSlice(),
        .severity_score = compliance.overall_score,
        .finding_count = compliance.critical_findings + compliance.high_findings + compliance.medium_findings + compliance.low_findings,
    });
}

fn addMemorySection(sections: *std.ArrayList(ReportSection), memory: *const memory_safety.BinarySafetyAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Memory Safety Analysis\n\n", .{});
    try w.print("- Unsafe Copy Operations: {}\n", .{memory.unsafe_copy_count});
    try w.print("- Format String Vulnerabilities: {}\n", .{memory.format_string_count});
    try w.print("- Memory Leaks: {}\n", .{memory.memory_leak_count});
    try w.print("- Buffer Overflow Potential: {}\n", .{memory.buffer_overflow_count});
    try w.print("- Null Dereferences: {}\n", .{memory.null_deref_count});
    try w.print("- Safety Gap Score: {d:.2}\n\n", .{memory.safety_gap_score});

    for (memory.findings) |f| {
        try w.print("- [CWE-{}] {s}\n", .{ f.cwe_id, f.description });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .memory_safety,
        .title = "Memory Safety Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = memory.safety_gap_score,
        .finding_count = memory.findings.len,
    });
}

fn addDependencySection(sections: *std.ArrayList(ReportSection), deps: *const dependency_checker.DependencyAnalysis, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Dependency Analysis\n\n", .{});
    try w.print("- Total Dependencies: {}\n", .{deps.total_dependencies});
    try w.print("- Vulnerable: {} | Outdated: {} | Unsigned: {}\n", .{ deps.vulnerable_count, deps.outdated_count, deps.unsigned_count });
    try w.print("- Supply Chain Score: {d:.2}%\n\n", .{deps.supply_chain_score});

    for (deps.findings) |f| {
        try w.print("- {s}", .{f.description});
        if (f.cve_id.len > 0) try w.print(" ({s})", .{f.cve_id});
        try w.writeByte('\n');
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .dependency_scan,
        .title = "Dependency Analysis",
        .content = try content.toOwnedSlice(),
        .severity_score = deps.supply_chain_score,
        .finding_count = deps.findings.len,
    });
}

fn addConfigSection(sections: *std.ArrayList(ReportSection), config: *const config_auditor.ConfigAudit, critical: *usize, high: *usize, medium: *usize, low: *usize, allocator: Allocator) !void {
    var content = std.ArrayList(u8).init(allocator);
    defer content.deinit();
    const w = content.writer();

    try w.print("## Configuration Audit\n\n", .{});
    try w.print("- Hardcoded Credentials: {}\n", .{config.hardcoded_credentials});
    try w.print("- Insecure Defaults: {}\n", .{config.insecure_defaults});
    try w.print("- Disabled Security Features: {}\n", .{config.disabled_security});
    try w.print("- Settings Checked: {}\n", .{config.total_settings_checked});
    try w.print("- Config Security Score: {d:.2}%\n\n", .{config.config_security_score});

    for (config.findings) |f| {
        try w.print("- [severity={}] {s}\n", .{ f.severity, f.description });
    }

    _ = critical;
    _ = high;
    _ = medium;
    _ = low;

    try sections.append(.{
        .section_type = .config_audit,
        .title = "Configuration Audit",
        .content = try content.toOwnedSlice(),
        .severity_score = config.config_security_score,
        .finding_count = config.findings.len,
    });
}

fn addRecommendations(sections: *std.ArrayList(ReportSection), _: Allocator) !void {
    const content =
        \\## Recommendations
        \\
        \\1. **Enable Compiler Security Features:** Use -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -Wl,-z,relro,-z,now
        \\2. **Implement Cryptographic Best Practices:** Use AEAD modes (GCM/ChaCha20-Poly1305), avoid ECB, use secure RNG
        \\3. **Secure Configuration Management:** Remove hardcoded credentials, use environment variables/vaults
        \\4. **Input Validation:** Validate all external inputs, use bounded string functions
        \\5. **Memory Safety:** Use safe string functions (strlcpy/strlcat), add null checks after allocation
        \\6. **Concurrency:** Ensure proper locking, avoid deadlocks, use atomic operations for shared data
        \\7. **Privacy Compliance:** Implement consent mechanisms, data minimization, retention policies
        \\8. **Regular Dependency Updates:** Keep dependencies updated, monitor CVEs
        \\9. **Firmware Integrity:** Enable secure boot, sign firmware images, implement rollback protection
        \\10. **Comprehensive Logging:** Implement audit logging for security events
        \\
        \\*Generated by IntegrityGap v2.1.0 - Commercial-Grade Binary Integrity Analysis Suite*
    ;

    try sections.append(.{
        .section_type = .recommendations,
        .title = "Recommendations",
        .content = content,
        .finding_count = 10,
    });
}

fn addAppendix(sections: *std.ArrayList(ReportSection), _: Allocator) !void {
    const content =
        \\## Appendix: Methodology
        \\
        \\IntegrityGap v2.1.0 performs comprehensive binary analysis using:
        \\
        \\- **Static Binary Analysis:** ELF/PE parsing, instruction decoding, control flow graph construction
        \\- **Integrity Gap Analysis:** Error handling, resource lifecycle, input validation, cryptographic patterns
        \\- **Concurrency Analysis:** Race condition detection, lock analysis, deadlock potential
        \\- **Taint Analysis:** Data flow tracking from untrusted sources to security-sensitive sinks
        \\- **Firmware Integrity:** Hash verification, signature detection, boot chain analysis
        \\- **Cryptographic Audit:** Algorithm strength, key management, mode analysis
        \\- **Privacy Analysis:** PII detection, consent mechanisms, GDPR/CCPA compliance
        \\- **Compliance Engine:** Automated PCI-DSS, HIPAA, SOC2, ISO 27001 checks
        \\- **Memory Safety:** Unsafe pattern detection, stack analysis, integer overflow
        \\- **Dependency Scanning:** CVE matching, license analysis, supply chain risks
        \\- **Configuration Audit:** Hardcoded secrets, security controls, default configurations
        \\
    ;

    try sections.append(.{
        .section_type = .appendix,
        .title = "Methodology",
        .content = content,
        .finding_count = 0,
    });
}

fn countSeverity(evidence: []const types.Evidence, min: u8, max: u8) usize {
    var count: usize = 0;
    for (evidence) |ev| {
        if (ev.severity >= min and ev.severity <= max) count += 1;
    }
    return count;
}

fn parser_countExecSections(image: types.BinaryImage) usize {
    var count: usize = 0;
    for (image.sections) |section| {
        if (section.executable) count += 1;
    }
    return count;
}

pub fn renderHtml(report: Report) ![]u8 {
    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    const w = buf.writer();
    try w.writeAll("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>");
    try w.writeAll(report.title);
    try w.writeAll("</title><style>body{font-family:monospace;margin:40px;background:#1e1e1e;color:#d4d4d4}");
    try w.writeAll("h1{color:#569cd6}h2{color:#4ec9b0}h3{color:#c586c0}.critical{color:#f44747}.high{color:#ce9178}");
    try w.writeAll(".medium{color:#dcdcaa}.low{color:#6a9955}pre{background:#2d2d2d;padding:10px;border-radius:4px}");
    try w.writeAll(".score{font-size:24px;font-weight:bold}.severity-high{color:#f44747}.severity-medium{color:#dcdcaa}");
    try w.writeAll("</style></head><body>");
    try w.print("<h1>{s}</h1>", .{report.title});
    try w.print("<p>Version: {s} | Target: {s} | Timestamp: {d}</p>", .{ report.version, report.target_path, report.timestamp });
    try w.print("<h2>Overall Score: <span class=\"score {s}\">{d:.1}%</span></h2>", .{ if (report.overall_score >= 70) "severity-medium" else "severity-high", report.overall_score });
    try w.print("<p>Critical: {} | High: {} | Medium: {} | Low: {} | Total: {}</p>", .{ report.critical_count, report.high_count, report.medium_count, report.low_count, report.total_findings });

    for (report.sections) |section| {
        try w.print("<h2>{s}</h2>", .{section.title});
        try w.print("<pre>{s}</pre>", .{section.content});
    }

    try w.writeAll("</body></html>");
    return buf.toOwnedSlice();
}

pub fn renderMarkdown(report: Report, allocator: Allocator) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();
    try w.print("# {s}\n\n", .{report.title});
    try w.print("**Version:** {s} | **Target:** {s} | **Overall Score:** {d:.1}%\n\n", .{ report.version, report.target_path, report.overall_score });
    try w.print("| Severity | Count |\n|----------|-------|\n", .{});
    try w.print("| Critical | {} |\n| High | {} |\n| Medium | {} |\n| Low | {} |\n| **Total** | **{}** |\n\n", .{ report.critical_count, report.high_count, report.medium_count, report.low_count, report.total_findings });

    for (report.sections) |section| {
        try w.writeAll(section.content);
        try w.writeByte('\n');
    }

    return buf.toOwnedSlice();
}

pub fn renderSarifFromAnalyses(
    allocator: Allocator,
    target_path: []const u8,
    sha256: [32]u8,
    integrity_analysis: ?*const types.Analysis,
    concurrency: ?*const concurrency_analyzer.ConcurrencyAnalysis,
    taint: ?*const taint_analyzer.TaintAnalysis,
    firmware: ?*const firmware_integrity.FirmwareAnalysis,
    crypto: ?*const crypto_auditor.CryptoAudit,
    privacy: ?*const privacy_analyzer.PrivacyAnalysis,
    compliance: ?*const compliance_engine.ComplianceSuite,
    memory: ?*const memory_safety.BinarySafetyAnalysis,
    dependencies: ?*const dependency_checker.DependencyAnalysis,
    config: ?*const config_auditor.ConfigAudit,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();

    try w.writeAll("{\n");
    try w.writeAll("  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
    try w.writeAll("  \"version\": \"2.1.0\",\n");
    try w.writeAll("  \"runs\": [\n    {\n");
    try w.writeAll("      \"tool\": {\n        \"driver\": {\n          \"name\": \"IntegrityGap\",\n          \"version\": \"2.1.0\",\n          \"informationUri\": \"https://github.com/IntegrityGap/IntegrityGap\"\n        }\n      },\n");
    try w.writeAll("      \"properties\": {\n");
    try w.writeAll("        \"target_path\": ");
    try writeSarifString(w, target_path);
    try w.writeAll(",\n");
    try w.writeAll("        \"sha256\": \"");
    try writeHexHashSarif(w, sha256);
    try w.writeAll("\"\n");
    try w.writeAll("      },\n");
    try w.writeAll("      \"results\": [\n");

    var first_result = true;

    if (integrity_analysis) |ia| {
        for (ia.evidence) |ev| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.print("        {{\n          \"ruleId\": \"IG-INTEGRITY\",\n          \"level\": \"{s}\",\n", .{severityToSarifLevel(ev.severity)});
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, ev.message);
            try w.writeAll(" },\n");
            try w.print("          \"locations\": [{{\n            \"physicalLocation\": {{\n              \"address\": {{ \"absoluteAddress\": {d} }},\n              \"artifactLocation\": {{ \"uri\": ", .{ev.address});
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"category\": ");
            try writeSarifString(w, ev.category);
            try w.writeAll(", \"severity\": ");
            try w.print("{d}", .{ev.severity});
            try w.writeAll(" }\n        }");
        }
    }

    if (concurrency) |c| {
        for (c.race_conditions) |rc| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.writeAll("        {\n          \"ruleId\": \"IG-CONCURRENCY-RACE\",\n          \"level\": \"error\",\n");
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, rc.description);
            try w.writeAll(" },\n");
            try w.print("          \"locations\": [{{\n            \"physicalLocation\": {{\n              \"address\": {{ \"absoluteAddress\": {d} }},\n              \"artifactLocation\": {{ \"uri\": ", .{rc.address});
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"concurrency\", \"type\": \"race_condition\" }\n        }");
        }
        for (c.threading_issues) |ti| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.writeAll("        {\n          \"ruleId\": \"IG-CONCURRENCY-THREAD\",\n          \"level\": \"warning\",\n");
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, ti.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"concurrency\", \"type\": \"threading_issue\" }\n        }");
        }
    }

    if (taint) |t| {
        for (t.propagations) |prop| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            const level = if (prop.severity == .critical) "error" else if (prop.severity == .high) "warning" else "note";
            try w.print("        {{\n          \"ruleId\": \"IG-TAINT\",\n          \"level\": \"{s}\",\n", .{level});
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, prop.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"taint\", \"source_type\": \"");
            try w.writeAll(@tagName(prop.source_type));
            try w.writeAll("\", \"sink_type\": \"");
            try w.writeAll(@tagName(prop.sink_type));
            try w.writeAll("\" }\n        }");
        }
    }

    if (firmware) |f| {
        for (f.findings) |finding| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.print("        {{\n          \"ruleId\": \"IG-FIRMWARE\",\n          \"level\": \"{s}\",\n", .{severityToSarifLevel(finding.severity)});
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, finding.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"firmware\" }\n        }");
        }
    }

    if (crypto) |cr| {
        for (cr.findings) |fnd| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.print("        {{\n          \"ruleId\": \"IG-CRYPTO\",\n          \"level\": \"{s}\",\n", .{severityToSarifLevel(fnd.severity)});
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, fnd.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"crypto\" }\n        }");
        }
    }

    if (privacy) |pr| {
        for (pr.findings) |fnd| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.writeAll("        {\n          \"ruleId\": \"IG-PRIVACY\",\n          \"level\": \"warning\",\n");
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, fnd.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"privacy\", \"gdpr_articles\": ");
            try writeSarifString(w, fnd.gdpr_articles);
            try w.writeAll(" }\n        }");
        }
    }

    if (compliance) |co| {
        for (co.reports) |report| {
            for (report.findings) |fnd| {
                if (fnd.status == .non_compliant or fnd.status == .partial) {
                    if (!first_result) try w.writeAll(",\n");
                    first_result = false;
                    const c_level = if (fnd.requirement.severity >= 80) "error" else "warning";
                    try w.print("        {{\n          \"ruleId\": \"IG-COMPLIANCE-{s}\",\n          \"level\": \"{s}\",\n", .{ @tagName(report.framework), c_level });
                    try w.writeAll("          \"message\": { \"text\": \"[");
                    try w.writeAll(fnd.requirement.requirement_id);
                    try w.writeAll("] ");
                    try w.writeAll(fnd.requirement.description);
                    try w.writeAll("\" },\n");
                    try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
                    try writeSarifString(w, target_path);
                    try w.writeAll(" }\n            }\n          }],\n");
                    try w.writeAll("          \"properties\": { \"module\": \"compliance\", \"framework\": \"");
                    try w.writeAll(@tagName(report.framework));
                    try w.writeAll("\", \"requirement_id\": \"");
                    try w.writeAll(fnd.requirement.requirement_id);
                    try w.writeAll("\" }\n        }");
                }
            }
        }
    }

    if (memory) |m| {
        for (m.findings) |fnd| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.print("        {{\n          \"ruleId\": \"IG-MEMORY-CWE-{}\",\n          \"level\": \"{s}\",\n", .{ fnd.cwe_id, severityToSarifLevel(fnd.severity) });
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, fnd.description);
            try w.writeAll(" },\n");
            try w.print("          \"locations\": [{{\n            \"physicalLocation\": {{\n              \"address\": {{ \"absoluteAddress\": {d} }},\n              \"artifactLocation\": {{ \"uri\": ", .{fnd.address});
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"memory_safety\", \"cwe\": ");
            try w.print("{d}", .{fnd.cwe_id});
            try w.writeAll(" }\n        }");
        }
    }

    if (dependencies) |d| {
        for (d.findings) |fnd| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.writeAll("        {\n          \"ruleId\": \"IG-DEPENDENCY\",\n          \"level\": \"warning\",\n");
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, fnd.description);
            try w.writeAll(" },\n");
            try w.writeAll("          \"locations\": [{\n            \"physicalLocation\": {\n              \"address\": { \"absoluteAddress\": 0 },\n              \"artifactLocation\": { \"uri\": ");
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"dependency\"");
            if (fnd.cve_id.len > 0) {
                try w.writeAll(", \"cve\": ");
                try writeSarifString(w, fnd.cve_id);
            }
            try w.writeAll(" }\n        }");
        }
    }

    if (config) |cf| {
        for (cf.findings) |fnd| {
            if (!first_result) try w.writeAll(",\n");
            first_result = false;
            try w.print("        {{\n          \"ruleId\": \"IG-CONFIG\",\n          \"level\": \"{s}\",\n", .{severityToSarifLevel(fnd.severity)});
            try w.writeAll("          \"message\": { \"text\": ");
            try writeSarifString(w, fnd.description);
            try w.writeAll(" },\n");
            try w.print("          \"locations\": [{{\n            \"physicalLocation\": {{\n              \"address\": {{ \"absoluteAddress\": {d} }},\n              \"artifactLocation\": {{ \"uri\": ", .{fnd.address});
            try writeSarifString(w, target_path);
            try w.writeAll(" }\n            }\n          }],\n");
            try w.writeAll("          \"properties\": { \"module\": \"config_audit\", \"issue_type\": \"");
            try w.writeAll(@tagName(fnd.issue_type));
            try w.writeAll("\" }\n        }");
        }
    }

    try w.writeAll("\n      ]\n    }\n  ]\n}\n");
    return buf.toOwnedSlice();
}

pub fn renderCsvFromAnalyses(
    allocator: Allocator,
    integrity_analysis: ?*const types.Analysis,
    concurrency: ?*const concurrency_analyzer.ConcurrencyAnalysis,
    taint: ?*const taint_analyzer.TaintAnalysis,
    firmware: ?*const firmware_integrity.FirmwareAnalysis,
    crypto: ?*const crypto_auditor.CryptoAudit,
    privacy: ?*const privacy_analyzer.PrivacyAnalysis,
    compliance: ?*const compliance_engine.ComplianceSuite,
    memory: ?*const memory_safety.BinarySafetyAnalysis,
    dependencies: ?*const dependency_checker.DependencyAnalysis,
    config: ?*const config_auditor.ConfigAudit,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();
    try w.writeAll("Module,Severity,Description,CWE,Framework,Address\n");

    if (integrity_analysis) |ia| {
        for (ia.evidence) |ev| {
            try w.print("IntegrityGap,{d},\"", .{ev.severity});
            try writeCsvEscaped(w, ev.message);
            try w.writeAll("\",,,0x");
            try w.print("{x}\n", .{ev.address});
        }
    }

    if (concurrency) |c| {
        for (c.race_conditions) |rc| {
            try w.writeAll("Concurrency,85,\"");
            try writeCsvEscaped(w, rc.description);
            try w.writeAll("\",,,0x");
            try w.print("{x}\n", .{rc.address});
        }
        for (c.threading_issues) |ti| {
            try w.writeAll("Concurrency,65,\"");
            try writeCsvEscaped(w, ti.description);
            try w.writeAll("\",,,\n");
        }
    }

    if (taint) |t| {
        for (t.propagations) |prop| {
            const sev = if (prop.severity == .critical) 90 else if (prop.severity == .high) 70 else 50;
            try w.print("Taint,{d},\"", .{sev});
            try writeCsvEscaped(w, prop.description);
            try w.writeAll("\",,,\n");
        }
    }

    if (firmware) |f| {
        for (f.findings) |fnd| {
            try w.print("Firmware,{d},\"", .{fnd.severity});
            try writeCsvEscaped(w, fnd.description);
            try w.writeAll("\",,,\n");
        }
    }

    if (crypto) |cr| {
        for (cr.findings) |fnd| {
            try w.print("Crypto,{d},\"", .{fnd.severity});
            try writeCsvEscaped(w, fnd.description);
            try w.writeAll("\",,,\n");
        }
    }

    if (privacy) |pr| {
        for (pr.findings) |fnd| {
            try w.writeAll("Privacy,75,\"");
            try writeCsvEscaped(w, fnd.description);
            try w.writeAll("\",,,\n");
        }
    }

    if (compliance) |co| {
        for (co.reports) |report| {
            for (report.findings) |fnd| {
                if (fnd.status == .non_compliant or fnd.status == .partial) {
                    try w.print("Compliance,{d},\"", .{fnd.requirement.severity});
                    try writeCsvEscaped(w, fnd.requirement.description);
                    try w.print("\",,{s},\n", .{@tagName(report.framework)});
                }
            }
        }
    }

    if (memory) |m| {
        for (m.findings) |fnd| {
            try w.print("MemorySafety,{d},\"", .{fnd.severity});
            try writeCsvEscaped(w, fnd.description);
            try w.print("\",CWE-{d},,0x", .{fnd.cwe_id});
            try w.print("{x}\n", .{fnd.address});
        }
    }

    if (dependencies) |d| {
        for (d.findings) |fnd| {
            try w.writeAll("Dependency,70,\"");
            try writeCsvEscaped(w, fnd.description);
            try w.writeAll("\",,,");
            if (fnd.cve_id.len > 0) {
                try w.writeAll(fnd.cve_id);
            }
            try w.writeByte('\n');
        }
    }

    if (config) |cf| {
        for (cf.findings) |fnd| {
            try w.print("ConfigAudit,{d},\"", .{fnd.severity});
            try writeCsvEscaped(w, fnd.description);
            try w.writeAll("\",,,0x");
            try w.print("{x}\n", .{fnd.address});
        }
    }

    return buf.toOwnedSlice();
}

pub fn renderJunitXmlFromAnalyses(
    allocator: Allocator,
    integrity_analysis: ?*const types.Analysis,
    concurrency: ?*const concurrency_analyzer.ConcurrencyAnalysis,
    taint: ?*const taint_analyzer.TaintAnalysis,
    firmware: ?*const firmware_integrity.FirmwareAnalysis,
    crypto: ?*const crypto_auditor.CryptoAudit,
    privacy: ?*const privacy_analyzer.PrivacyAnalysis,
    compliance: ?*const compliance_engine.ComplianceSuite,
    memory: ?*const memory_safety.BinarySafetyAnalysis,
    dependencies: ?*const dependency_checker.DependencyAnalysis,
    config: ?*const config_auditor.ConfigAudit,
) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();

    var total: usize = 0;
    var failures: usize = 0;
    const errors: usize = 0;

    if (integrity_analysis) |ia| { total += ia.evidence.len; for (ia.evidence) |ev| { if (ev.severity >= 70) failures += 1; } }
    if (concurrency) |c| { total += c.race_conditions.len + c.threading_issues.len; failures += c.race_conditions.len; }
    if (taint) |t| { total += t.propagations.len; failures += t.critical_severity_count + t.high_severity_count; }
    if (firmware) |f| { total += f.findings.len; failures += countSeverityFindings(f.findings, 70); }
    if (crypto) |cr| { total += cr.findings.len; failures += countSeverityFindings(cr.findings, 60); }
    if (privacy) |pr| { total += pr.findings.len; failures += pr.findings.len / 2; }
    if (compliance) |co| { total += co.critical_findings + co.high_findings + co.medium_findings + co.low_findings; failures += co.critical_findings + co.high_findings; }
    if (memory) |m| { total += m.findings.len; failures += countSeverityFindings(m.findings, 60); }
    if (dependencies) |d| { total += d.findings.len; failures += d.vulnerable_count; }
    if (config) |cf| { total += cf.findings.len; failures += countSeverityFindings(cf.findings, 70); }

    try w.writeAll("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    try w.print("<testsuite name=\"IntegrityGap\" tests=\"{d}\" failures=\"{d}\" errors=\"{d}\">\n", .{ total, failures, errors });

    if (integrity_analysis) |ia| {
        try w.print("  <testcase name=\"IntegrityGap Analysis\" classname=\"integrity_gap\" assertions=\"{d}\">\n", .{ia.evidence.len});
        for (ia.evidence) |ev| {
            if (ev.severity >= 70) {
                try w.writeAll("    <failure message=\"");
                try writeXmlEscaped(w, ev.message);
                try w.print("\" type=\"integrity_violation\"/>\n", .{});
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    if (concurrency) |c| {
        try w.print("  <testcase name=\"Concurrency Analysis\" classname=\"concurrency\">\n", .{});
        for (c.race_conditions) |rc| {
            try w.writeAll("    <failure message=\"");
            try writeXmlEscaped(w, rc.description);
            try w.writeAll("\" type=\"race_condition\"/>\n");
        }
        try w.writeAll("  </testcase>\n");
    }

    if (taint) |t| {
        try w.print("  <testcase name=\"Taint Analysis\" classname=\"taint\">\n", .{});
        for (t.propagations) |prop| {
            if (prop.severity == .critical or prop.severity == .high) {
                try w.writeAll("    <failure message=\"");
                try writeXmlEscaped(w, prop.description);
                try w.writeAll("\" type=\"taint_flow\"/>\n");
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    if (firmware) |f| {
        try w.print("  <testcase name=\"Firmware Integrity\" classname=\"firmware\">\n", .{});
        for (f.findings) |fnd| {
            if (fnd.severity >= 70) {
                try w.writeAll("    <failure message=\"");
                try writeXmlEscaped(w, fnd.description);
                try w.writeAll("\" type=\"firmware_violation\"/>\n");
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    if (crypto) |cr| {
        try w.print("  <testcase name=\"Cryptographic Audit\" classname=\"crypto\">\n", .{});
        for (cr.findings) |fnd| {
            if (fnd.severity >= 60) {
                try w.writeAll("    <failure message=\"");
                try writeXmlEscaped(w, fnd.description);
                try w.writeAll("\" type=\"crypto_weakness\"/>\n");
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    if (compliance) |co| {
        for (co.reports) |report| {
            try w.print("  <testcase name=\"Compliance: {s}\" classname=\"compliance\">\n", .{@tagName(report.framework)});
            for (report.findings) |fnd| {
                if (fnd.status == .non_compliant or fnd.status == .partial) {
                    try w.writeAll("    <failure message=\"[");
                    try w.writeAll(fnd.requirement.requirement_id);
                    try w.writeAll("] ");
                    try writeXmlEscaped(w, fnd.requirement.description);
                    try w.writeAll("\" type=\"compliance_violation\"/>\n");
                }
            }
            try w.writeAll("  </testcase>\n");
        }
    }

    if (memory) |m| {
        try w.print("  <testcase name=\"Memory Safety Analysis\" classname=\"memory_safety\">\n", .{});
        for (m.findings) |fnd| {
            if (fnd.severity >= 60) {
                try w.writeAll("    <failure message=\"[CWE-");
                try w.print("{d}", .{fnd.cwe_id});
                try w.writeAll("] ");
                try writeXmlEscaped(w, fnd.description);
                try w.writeAll("\" type=\"memory_safety\"/>\n");
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    if (dependencies) |d| {
        try w.print("  <testcase name=\"Dependency Analysis\" classname=\"dependency\">\n", .{});
        for (d.findings) |fnd| {
            try w.writeAll("    <failure message=\"");
            try writeXmlEscaped(w, fnd.description);
            if (fnd.cve_id.len > 0) {
                try w.writeAll(" (");
                try w.writeAll(fnd.cve_id);
                try w.writeAll(")");
            }
            try w.writeAll("\" type=\"dependency_vulnerability\"/>\n");
        }
        try w.writeAll("  </testcase>\n");
    }

    if (config) |cf| {
        try w.print("  <testcase name=\"Configuration Audit\" classname=\"config_audit\">\n", .{});
        for (cf.findings) |fnd| {
            if (fnd.severity >= 70) {
                try w.writeAll("    <failure message=\"");
                try writeXmlEscaped(w, fnd.description);
                try w.writeAll("\" type=\"config_violation\"/>\n");
            }
        }
        try w.writeAll("  </testcase>\n");
    }

    try w.writeAll("</testsuite>\n");
    return buf.toOwnedSlice();
}

fn severityToSarifLevel(severity: u8) []const u8 {
    if (severity >= 80) return "error";
    if (severity >= 50) return "warning";
    if (severity >= 20) return "note";
    return "none";
}

fn countSeverityFindings(findings: anytype, threshold: u8) usize {
    var count: usize = 0;
    for (findings) |f| {
        if (f.severity >= threshold) count += 1;
    }
    return count;
}

fn writeSarifString(w: anytype, value: []const u8) !void {
    try w.writeByte('"');
    for (value) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11...12, 14...31 => {
                try w.print("\\u00{x}", .{c});
            },
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

fn writeHexHashSarif(w: anytype, hash: [32]u8) !void {
    const hex = "0123456789abcdef";
    for (hash) |byte| {
        try w.writeByte(hex[byte >> 4]);
        try w.writeByte(hex[byte & 0x0f]);
    }
}

fn writeCsvEscaped(w: anytype, value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '"' => try w.writeAll("\"\""),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            else => try w.writeByte(c),
        }
    }
}

fn writeXmlEscaped(w: anytype, value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '&' => try w.writeAll("&amp;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&apos;"),
            else => try w.writeByte(c),
        }
    }
}
