const std = @import("std");
const types = @import("types.zig");
const parser = @import("core/parser.zig");
const decoder = @import("core/decoder.zig");
const analyzer = @import("core/analyzer.zig");
const reporter = @import("output/reporter.zig");
const signatures = @import("core/signatures.zig");
const utils = @import("core/utils.zig");
const concurrency_analyzer = @import("analysis/concurrency_analyzer.zig");
const taint_analyzer = @import("analysis/taint_analyzer.zig");
const firmware_integrity = @import("analysis/firmware_integrity.zig");
const crypto_auditor = @import("analysis/crypto_auditor.zig");
const privacy_analyzer = @import("analysis/privacy_analyzer.zig");
const compliance_engine = @import("analysis/compliance_engine.zig");
const memory_safety = @import("analysis/memory_safety.zig");
const dependency_checker = @import("analysis/dependency_checker.zig");
const config_auditor = @import("analysis/config_auditor.zig");
const string_analyzer = @import("analysis/string_analyzer.zig");
const report_engine = @import("output/report_engine.zig");
const config_file = @import("infra/config_file.zig");
const result_cache = @import("infra/result_cache.zig");
const false_positive_reducer = @import("postproc/false_positive_reducer.zig");
const remediation_engine = @import("postproc/remediation_engine.zig");
const cvss_scorer = @import("postproc/cvss_scorer.zig");

const Allocator = types.Allocator;
const default_max_bytes = types.default_max_bytes;

pub const AnalysisMode = enum {
    all,
    integrity_gap,
    concurrency,
    taint,
    firmware,
    crypto,
    privacy,
    compliance,
    memory,
    dependencies,
    config,
    strings,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var target_path: ?[]const u8 = null;
    var json_path: ?[]const u8 = null;
    var dot_path: ?[]const u8 = null;
    var diff_path: ?[]const u8 = null;
    var baseline_path: ?[]const u8 = null;
    var plain = false;
    var max_bytes: usize = default_max_bytes;
    var verbose = false;
    var output_html: ?[]const u8 = null;
    var output_md: ?[]const u8 = null;
    var output_sarif: ?[]const u8 = null;
    var output_csv: ?[]const u8 = null;
    var output_junit: ?[]const u8 = null;
    var batch_mode = false;
    var mode: AnalysisMode = .all;
    var mode_set = false;
    var compliance_framework: ?[]const u8 = null;
    var report_only = false;
    var baseline_dir: ?[]const u8 = null;
    var firmware_check = false;
    var batch_file: ?[]const u8 = null;
    var cache_enabled = true;
    var cache_directory: ?[]const u8 = null;
    var min_severity: u8 = 0;
    var max_findings: ?usize = null;
    var fp_red_enabled = false;
    var enable_remediation = false;
    var enable_cvss = false;
    var config_file_path: ?[]const u8 = null;

    var i: usize = 1;
    const stderr = std.io.getStdErr().writer();
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const next = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, arg, "--target")) {
            i += 1;
            target_path = next;
        } else if (std.mem.eql(u8, arg, "--json")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --json requires a path\n"); std.process.exit(1); }
            i += 1;
            json_path = next;
        } else if (std.mem.eql(u8, arg, "--dot")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --dot requires a path\n"); std.process.exit(1); }
            i += 1;
            dot_path = next;
        } else if (std.mem.eql(u8, arg, "--diff")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --diff requires a path\n"); std.process.exit(1); }
            i += 1;
            diff_path = next;
        } else if (std.mem.eql(u8, arg, "--baseline")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --baseline requires a path\n"); std.process.exit(1); }
            i += 1;
            baseline_path = next;
        } else if (std.mem.eql(u8, arg, "--plain")) {
            plain = true;
        } else if (std.mem.eql(u8, arg, "--max-bytes")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --max-bytes requires a value\n"); std.process.exit(1); }
            i += 1;
            max_bytes = std.fmt.parseInt(usize, next, 10) catch default_max_bytes;
        } else if (std.mem.eql(u8, arg, "--verbose") or std.mem.eql(u8, arg, "-v")) {
            verbose = true;
        } else if (std.mem.eql(u8, arg, "--html")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --html requires a path\n"); std.process.exit(1); }
            i += 1;
            output_html = next;
        } else if (std.mem.eql(u8, arg, "--markdown") or std.mem.eql(u8, arg, "--md")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --markdown requires a path\n"); std.process.exit(1); }
            i += 1;
            output_md = next;
        } else if (std.mem.eql(u8, arg, "--sarif")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --sarif requires a path\n"); std.process.exit(1); }
            i += 1;
            output_sarif = next;
        } else if (std.mem.eql(u8, arg, "--mode")) {
            if (next.len == 0) {
                try stderr.writeAll("[IntegrityGap] --mode requires a value\n");
                printUsage();
                std.process.exit(1);
            }
            if (mode_set) {
                try stderr.writeAll("[IntegrityGap] multiple --mode flags specified\n");
                std.process.exit(1);
            }
            i += 1;
            mode = parseMode(next);
            mode_set = true;
        } else if (std.mem.eql(u8, arg, "--compliance-framework")) {
            i += 1;
            compliance_framework = next;
        } else if (std.mem.eql(u8, arg, "--report-only")) {
            report_only = true;
        } else if (std.mem.eql(u8, arg, "--all")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .all; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--integrity-gap")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .integrity_gap; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--concurrency")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .concurrency; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--taint")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .taint; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--crypto")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .crypto; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--privacy")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .privacy; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--memory")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .memory; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--dependencies")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .dependencies; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--config")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .config; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--strings")) {
            if (mode_set) { try stderr.writeAll("[IntegrityGap] multiple mode flags specified\n"); std.process.exit(1); }
            mode = .strings; mode_set = true;
        } else if (std.mem.eql(u8, arg, "--compliance")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) {
                try stderr.writeAll("[IntegrityGap] --compliance requires a framework name\n");
                std.process.exit(1);
            }
            mode = .compliance;
            compliance_framework = next;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--firmware")) {
            firmware_check = true;
        } else if (std.mem.eql(u8, arg, "--csv")) {
            i += 1;
            output_csv = next;
        } else if (std.mem.eql(u8, arg, "--junit")) {
            i += 1;
            output_junit = next;
        } else if (std.mem.eql(u8, arg, "--cache-enabled")) {
            cache_enabled = true;
        } else if (std.mem.eql(u8, arg, "--cache-directory")) {
            i += 1;
            cache_directory = next;
        } else if (std.mem.eql(u8, arg, "--min-severity")) {
            i += 1;
            min_severity = parseSeverity(next);
        } else if (std.mem.eql(u8, arg, "--max-findings")) {
            i += 1;
            max_findings = std.fmt.parseInt(usize, next, 10) catch null;
        } else if (std.mem.eql(u8, arg, "--fp-reduction")) {
            fp_red_enabled = true;
        } else if (std.mem.eql(u8, arg, "--enable-remediation")) {
            enable_remediation = true;
        } else if (std.mem.eql(u8, arg, "--enable-cvss")) {
            enable_cvss = true;
        } else if (std.mem.eql(u8, arg, "--config-file")) {
            i += 1;
            config_file_path = next;
        } else if (std.mem.eql(u8, arg, "--batch")) {
            if (next.len == 0 or std.mem.startsWith(u8, next, "-")) { try stderr.writeAll("[IntegrityGap] --batch requires a file\n"); std.process.exit(1); }
            i += 1;
            batch_file = next;
            batch_mode = true;
        } else if (std.mem.eql(u8, arg, "--baseline-dir")) {
            i += 1;
            baseline_dir = next;
        } else if (std.mem.eql(u8, arg, "--version")) {
            const out = std.io.getStdOut().writer();
            try out.writeAll("IntegrityGap v2.1.0\n");
            return;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printUsage();
            return;
        } else if (!std.mem.startsWith(u8, arg, "-") and target_path == null) {
            target_path = arg;
        } else {
            try stderr.print("[IntegrityGap] unknown option: {s}\n", .{arg});
            printUsage();
            std.process.exit(1);
        }
    }

    if (batch_mode) {
        if (batch_file) |bf| {
            return runBatchMode(allocator, bf, verbose, mode, json_path, dot_path, output_html, output_md, output_sarif, output_csv, output_junit, fp_red_enabled, enable_remediation, enable_cvss, min_severity, max_findings, cache_enabled, cache_directory);
        }
    }

    if (target_path == null) {
        printUsage();
        std.process.exit(1);
    }

    const target = target_path.?;

    if (report_only) {
        return runReportOnly();
    }

    if (baseline_path) |base_path| {
        return runDiffMode(allocator, target, base_path, max_bytes, verbose, json_path);
    }

    if (diff_path) |other_path| {
        return runDiffMode(allocator, target, other_path, max_bytes, verbose, json_path);
    }

    if (firmware_check and output_html == null and output_md == null and output_sarif == null) {
        return runFirmwareAnalysis(allocator, target, max_bytes, verbose, output_html, output_md);
    }

    return runFullAnalysis(allocator, target, max_bytes, verbose, mode, compliance_framework, json_path, dot_path, output_html, output_md, output_sarif, output_csv, output_junit, plain, fp_red_enabled, enable_remediation, enable_cvss, min_severity, max_findings, cache_enabled, cache_directory);
}

fn parseMode(name: []const u8) AnalysisMode {
    const modes = [_]struct { name: []const u8, mode: AnalysisMode }{
        .{ .name = "all", .mode = .all },
        .{ .name = "integrity-gap", .mode = .integrity_gap },
        .{ .name = "concurrency", .mode = .concurrency },
        .{ .name = "taint", .mode = .taint },
        .{ .name = "firmware", .mode = .firmware },
        .{ .name = "crypto", .mode = .crypto },
        .{ .name = "privacy", .mode = .privacy },
        .{ .name = "compliance", .mode = .compliance },
        .{ .name = "memory", .mode = .memory },
        .{ .name = "dependencies", .mode = .dependencies },
        .{ .name = "config", .mode = .config },
        .{ .name = "strings", .mode = .strings },
    };
    for (modes) |entry| {
        if (std.mem.eql(u8, name, entry.name)) return entry.mode;
    }
    return .all;
}

fn runFullAnalysis(allocator: Allocator, path: []const u8, max_bytes: usize, verbose: bool, mode: AnalysisMode, compliance_framework: ?[]const u8, json_path: ?[]const u8, dot_path: ?[]const u8, output_html: ?[]const u8, output_md: ?[]const u8, output_sarif: ?[]const u8, output_csv: ?[]const u8, output_junit: ?[]const u8, plain: bool, fp_red_enabled: bool, enable_remediation: bool, enable_cvss: bool, min_severity: u8, max_findings: ?usize, cache_enabled: bool, cache_directory: ?[]const u8) !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    var cache_store: ?result_cache.CacheStore = null;
    defer if (cache_store) |*cs| cs.deinit();

    if (cache_enabled) {
        cache_store = result_cache.CacheStore.init(allocator, .{
            .directory = cache_directory orelse ".integritygap_cache",
        });
        const file_hash = result_cache.hashFile(allocator, path) catch |err| h: {
            if (verbose) try stderr.print("[IntegrityGap] Cache hash error: {}\n", .{err});
            break :h null;
        };
        if (file_hash) |hash| {
            if (cache_store.?.get(path, hash)) |cached| {
                defer allocator.free(cached);
                if (verbose) try stderr.print("[IntegrityGap] Cache hit for: {s}\n", .{path});
                try stdout.writeAll(cached);
                return;
            }
            if (verbose) try stderr.print("[IntegrityGap] Cache miss for: {s}\n", .{path});
        }
    }

    if (verbose) try stderr.print("[IntegrityGap] Analyzing: {s}\n", .{path});

    var analysis = try analyzer.analyzeTarget(allocator, path, max_bytes, verbose);
    defer analysis.deinit(allocator);

    if (verbose) try stderr.print("[IntegrityGap] Format: {s}/{s}, Functions: {}, Imports: {}\n", .{
        @tagName(analysis.image.format), @tagName(analysis.image.arch),
        analysis.functions.len, analysis.image.imports.len,
    });

    if (compliance_framework) |fw| {
        const framework = parseComplianceFramework(fw);
        var compliance_report = try compliance_engine.runComplianceCheck(allocator, framework, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        defer compliance_report.deinit(allocator);
        if (json_path) |jp| {
            try writeComplianceJson(jp, compliance_report);
            try writeComplianceJsonToWriter(stdout, compliance_report);
        }
        try writeComplianceStdout(compliance_report);
        return;
    }

    if (mode == .integrity_gap or mode == .all) {
        try runIntegrityGapOutput(allocator, &analysis, json_path, dot_path, plain);
    } else if (json_path) |jp| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try reporter.writeAnalysisJson(buf.writer(), analysis);
        var file = try std.fs.cwd().createFile(jp, .{ .truncate = true });
        defer file.close();
        try file.writeAll(buf.items);
        try std.io.getStdOut().writer().writeAll(buf.items);
    }

    var firmware_result: ?firmware_integrity.FirmwareAnalysis = null;
    var concurrency_result: ?concurrency_analyzer.ConcurrencyAnalysis = null;
    var taint_result: ?taint_analyzer.TaintAnalysis = null;
    var crypto_result: ?crypto_auditor.CryptoAudit = null;
    var privacy_result: ?privacy_analyzer.PrivacyAnalysis = null;
    var compliance_result: ?compliance_engine.ComplianceSuite = null;
    var memory_result: ?memory_safety.BinarySafetyAnalysis = null;
    var deps_result: ?dependency_checker.DependencyAnalysis = null;
    var config_result: ?config_auditor.ConfigAudit = null;

    if (mode == .firmware or mode == .all) {
        const firmware = try firmware_integrity.analyzeFirmware(allocator, analysis.bytes, path);
        firmware_result = firmware;
        if (verbose) try stderr.print("[IntegrityGap] Firmware: format={s}, score={d:.2}%\n", .{
            @tagName(firmware.format), firmware.integrity_score,
        });
        if (plain) try printFirmwareSummary(firmware);
    }

    if (mode == .concurrency or mode == .all) {
        const concurrency = try concurrency_analyzer.analyzeConcurrency(allocator, analysis.instructions, analysis.image, analysis.functions);
        concurrency_result = concurrency;
        if (verbose) try stderr.print("[IntegrityGap] Concurrency: races={}, issues={}, score={d:.2}\n", .{
            concurrency.race_conditions.len, concurrency.threading_issues.len, concurrency.concurrency_gap_score,
        });
        if (plain) try printConcurrencySummary(concurrency);
    }

    if (mode == .taint or mode == .all) {
        const taint = try taint_analyzer.analyzeTaint(allocator, analysis.instructions, analysis.image, analysis.functions, analysis.call_edges);
        taint_result = taint;
        if (verbose) try stderr.print("[IntegrityGap] Taint: sources={}, sinks={}, unvalidated={}/{}, score={d:.2}\n", .{
            taint.sources.len, taint.sinks.len, taint.unvalidated_paths, taint.total_paths, taint.taint_gap_score,
        });
        if (plain) try printTaintSummary(taint);
    }

    if (mode == .crypto or mode == .all) {
        const crypto = try crypto_auditor.auditCrypto(allocator, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        crypto_result = crypto;
        if (verbose) try stderr.print("[IntegrityGap] Crypto: usages={}, weak={}, hardcoded={}, score={d:.2}\n", .{
            crypto.cipher_usages.len, crypto.weak_cipher_count, crypto.hardcoded_key_count, crypto.crypto_gap_score,
        });
        if (plain) try printCryptoSummary(crypto);
    }

    if (mode == .privacy or mode == .all) {
        const privacy = try privacy_analyzer.analyzePrivacy(allocator, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        privacy_result = privacy;
        if (verbose) try stderr.print("[IntegrityGap] Privacy: findings={}, GDPR={d:.1}%, CCPA={d:.1}%, score={d:.2}\n", .{
            privacy.findings.len, privacy.gdpr_compliance_score, privacy.ccpa_compliance_score, privacy.privacy_gap_score,
        });
        if (plain) try printPrivacySummary(privacy);
    }

    if (mode == .compliance or mode == .all) {
        const compliance = try compliance_engine.runFullComplianceSuite(allocator, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        compliance_result = compliance;
        if (verbose) try stderr.print("[IntegrityGap] Compliance: overall={d:.1}%, critical={}, high={}, medium={}\n", .{
            compliance.overall_score, compliance.critical_findings, compliance.high_findings, compliance.medium_findings,
        });
        if (plain) try printComplianceSummary(compliance);
    }

    if (mode == .memory or mode == .all) {
        const memory = try memory_safety.analyzeMemorySafety(allocator, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        memory_result = memory;
        if (verbose) try stderr.print("[IntegrityGap] Memory: unsafe_copies={}, format_strings={}, leaks={}, score={d:.2}\n", .{
            memory.unsafe_copy_count, memory.format_string_count, memory.memory_leak_count, memory.safety_gap_score,
        });
        if (plain) try printMemorySummary(memory);
    }

    if (mode == .dependencies or mode == .all) {
        const deps = try dependency_checker.analyzeDependencies(allocator, analysis.bytes, analysis.image);
        deps_result = deps;
        if (verbose) try stderr.print("[IntegrityGap] Dependencies: total={}, vulnerable={}, score={d:.2}\n", .{
            deps.total_dependencies, deps.vulnerable_count, deps.supply_chain_score,
        });
        if (plain) try printDependencySummary(deps);
    }

    if (mode == .config or mode == .all) {
        const config = try config_auditor.auditConfiguration(allocator, analysis.bytes, analysis.instructions, analysis.image, analysis.functions);
        config_result = config;
        if (verbose) try stderr.print("[IntegrityGap] Config: credentials={}, defaults={}, disabled={}, score={d:.2}\n", .{
            config.hardcoded_credentials, config.insecure_defaults, config.disabled_security, config.config_security_score,
        });
        if (plain) try printConfigSummary(config);
    }

    var string_result: ?string_analyzer.StringAnalysis = null;
    if (mode == .strings or mode == .all) {
        const sa = try string_analyzer.analyzeStrings(allocator, analysis.bytes);
        string_result = sa;
        if (verbose) try stderr.print("[IntegrityGap] Strings: total={}, urls={}, ips={}, paths={}, registry={}, shell={}, crypto_keys={}, emails={}, jwt={}, base64={}\n", .{
            sa.total_strings, sa.url_count, sa.ip_count, sa.path_count, sa.registry_count, sa.shell_count, sa.crypto_key_count, sa.email_count, sa.jwt_count, sa.base64_count,
        });
        if (plain) try printStringSummary(sa);
    }

    if (memory_result) |m| { analysis.summary.scores.memory_safety = m.safety_gap_score; }
    if (deps_result) |d| { analysis.summary.scores.supply_chain = d.supply_chain_score; }
    if (config_result) |c| { analysis.summary.scores.configuration = c.config_security_score; }

    if (taint_result) |t| {
        analysis.summary.scores.input_validation = utils.clamp100(analysis.summary.scores.input_validation + t.taint_gap_score * 0.10);
    }
    if (crypto_result) |cr| {
        analysis.summary.scores.cryptographic = utils.clamp100(analysis.summary.scores.cryptographic + cr.crypto_gap_score * 0.10);
    }
    if (privacy_result) |pr| {
        analysis.summary.scores.logging_auditability = utils.clamp100(analysis.summary.scores.logging_auditability + pr.privacy_gap_score * 0.08);
    }
    if (compliance_result) |co| {
        analysis.summary.scores.error_handling = utils.clamp100(analysis.summary.scores.error_handling + co.overall_score * 0.08);
    }

    analysis.summary.aggregate_gap = analysis.summary.scores.aggregate();
    analysis.summary.anomaly_confidence = utils.clamp100(analysis.summary.aggregate_gap * 1.25);
    analyzer.recalculateThreat(&analysis.summary, analysis.profiles);

    if (min_severity > 0 or max_findings != null) {
        analysis.evidence = try filterEvidenceBySeverity(allocator, analysis.evidence, analysis.profiles, min_severity, max_findings);
    }

    if (fp_red_enabled) {
        var reduction = try false_positive_reducer.reduceFalsePositives(allocator, analysis.evidence, analysis.instructions, analysis.image, analysis.functions);
        defer reduction.deinit(allocator);
        if (verbose) try stderr.print("[IntegrityGap] FP Reduction: {d} false positives removed, {d} remaining\n", .{ reduction.removed_count, reduction.final_count });
    }

    if (enable_remediation) {
        var remediation = try remediation_engine.generateRemediations(allocator, analysis.evidence);
        defer remediation.deinit(allocator);
        if (verbose) try stderr.print("[IntegrityGap] Remediation: {d} suggestions ({d} immediate, {d} short-term), ~{d}h total\n", .{
            remediation.suggestions.len, remediation.immediate_count, remediation.short_term_count, remediation.total_effort_hours,
        });
        if (plain) {
            const out = std.io.getStdOut().writer();
            try out.print("\n=== Remediation Suggestions ===\n", .{});
            for (remediation.suggestions) |s| {
                try out.print("  [{s}] {s} (~{d}h)\n", .{ @tagName(s.priority), s.title, s.effort_hours });
            }
        }
    }

    if (enable_cvss) {
        var total_cvss: f64 = 0;
        var scored: usize = 0;
        for (analysis.evidence) |ev| {
            if (cvss_scorer.scoreEvidence(ev, allocator)) |score| {
                total_cvss += score.base_score;
                scored += 1;
            } else |_| {}
        }
        if (scored > 0) {
            const avg = total_cvss / @as(f64, @floatFromInt(scored));
            if (verbose) try stderr.print("[IntegrityGap] CVSS: avg {d:.1} across {d} findings\n", .{ avg, scored });
            if (plain) {
                const out = std.io.getStdOut().writer();
                const sev_label: []const u8 = if (avg >= 9.0) "critical" else if (avg >= 7.0) "high" else if (avg >= 4.0) "medium" else if (avg >= 0.1) "low" else "none";
                try out.print("\n=== CVSS Scoring ===\n  Average Base Score: {d:.1} ({s}) across {d} findings\n", .{
                    avg, sev_label, scored,
                });
            }
        }
    }

    if (mode == .all and (output_html != null or output_md != null or output_sarif != null)) {
        var report = try report_engine.generateComprehensiveReport(
            allocator, path, analysis.sha256,
            .json_verbose, &analysis,
            if (concurrency_result) |*r| r else null,
            if (taint_result) |*r| r else null,
            if (firmware_result) |*r| r else null,
            if (crypto_result) |*r| r else null,
            if (privacy_result) |*r| r else null,
            if (compliance_result) |*r| r else null,
            if (memory_result) |*r| r else null,
            if (deps_result) |*r| r else null,
            if (config_result) |*r| r else null,
        );
        defer report.deinit(allocator);

        if (output_html) |html_path| {
            const html = try report_engine.renderHtml(report);
            defer std.heap.page_allocator.free(html);
            var file = try std.fs.cwd().createFile(html_path, .{ .truncate = true });
            defer file.close();
            try file.writeAll(html);
            if (verbose) try stderr.print("[IntegrityGap] HTML report: {s}\n", .{html_path});
        }

        if (output_md) |md_path| {
            const md = try report_engine.renderMarkdown(report, allocator);
            defer allocator.free(md);
            var file = try std.fs.cwd().createFile(md_path, .{ .truncate = true });
            defer file.close();
            try file.writeAll(md);
            if (verbose) try stderr.print("[IntegrityGap] Markdown report: {s}\n", .{md_path});
        }

        if (output_sarif) |sarif_path| {
            const sarif = try report_engine.renderSarifFromAnalyses(
                allocator, path, analysis.sha256,
                &analysis,
                if (concurrency_result) |*r| r else null,
                if (taint_result) |*r| r else null,
                if (firmware_result) |*r| r else null,
                if (crypto_result) |*r| r else null,
                if (privacy_result) |*r| r else null,
                if (compliance_result) |*r| r else null,
                if (memory_result) |*r| r else null,
                if (deps_result) |*r| r else null,
                if (config_result) |*r| r else null,
            );
            defer allocator.free(sarif);
            var file = try std.fs.cwd().createFile(sarif_path, .{ .truncate = true });
            defer file.close();
            try file.writeAll(sarif);
            if (verbose) try stderr.print("[IntegrityGap] SARIF report: {s}\n", .{sarif_path});
        }

        if (plain) {
            try printReportSummary(report, analysis);
        }
    }

    if (output_csv) |csv_path| {
        try reporter.writeCsv(csv_path, analysis);
        if (verbose) try stderr.print("[IntegrityGap] CSV output: {s}\n", .{csv_path});
    }

    if (output_junit) |junit_path| {
        const junit = try report_engine.renderJunitXmlFromAnalyses(
            allocator, &analysis,
            if (concurrency_result) |*r| r else null,
            if (taint_result) |*r| r else null,
            if (firmware_result) |*r| r else null,
            if (crypto_result) |*r| r else null,
            if (privacy_result) |*r| r else null,
            if (compliance_result) |*r| r else null,
            if (memory_result) |*r| r else null,
            if (deps_result) |*r| r else null,
            if (config_result) |*r| r else null,
        );
        defer allocator.free(junit);
        var file = try std.fs.cwd().createFile(junit_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(junit);
        if (verbose) try stderr.print("[IntegrityGap] JUnit XML output: {s}\n", .{junit_path});
    }

    if (cache_store) |*cs| {
        var json_buf = std.ArrayList(u8).init(allocator);
        defer json_buf.deinit();
        const w = json_buf.writer();
        reporter.writeAnalysisJson(w, analysis) catch {};
        const file_hash = result_cache.hashFile(allocator, path) catch |err| h: {
            if (verbose) try stderr.print("[IntegrityGap] Cache-store hash error: {}\n", .{err});
            break :h null;
        };
        if (file_hash) |hash| {
            cs.set(path, hash, json_buf.items) catch |err| {
                if (verbose) try stderr.print("[IntegrityGap] Cache store error: {}\n", .{err});
            };
            if (verbose) try stderr.print("[IntegrityGap] Cache stored for: {s}\n", .{path});
        }
    }

    if (firmware_result) |*f| f.deinit(allocator);
    if (concurrency_result) |*c| c.deinit(allocator);
    if (taint_result) |*t| t.deinit(allocator);
    if (crypto_result) |*c| c.deinit(allocator);
    if (privacy_result) |*p| p.deinit(allocator);
    if (compliance_result) |*c| c.deinit(allocator);
    if (memory_result) |*m| m.deinit(allocator);
    if (deps_result) |*d| d.deinit(allocator);
    if (config_result) |*c| c.deinit(allocator);
    if (string_result) |*s| s.deinit(allocator);
}

fn runIntegrityGapOutput(allocator: Allocator, analysis: *const types.Analysis, json_path: ?[]const u8, dot_path: ?[]const u8, plain: bool) !void {
    if (plain) try reporter.writePlain(analysis.*);
    if (json_path) |path| {
        var buf = std.ArrayList(u8).init(allocator);
        defer buf.deinit();
        try reporter.writeAnalysisJson(buf.writer(), analysis.*);
        var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.writeAll(buf.items);
        try std.io.getStdOut().writer().writeAll(buf.items);
    } else if (dot_path == null and !plain) {
        try reporter.writeJsonStdout(analysis.*);
    }
    if (dot_path) |path| try reporter.writeDot(path, analysis.*);
}

fn runDiffMode(allocator: Allocator, target: []const u8, other: []const u8, max_bytes: usize, verbose: bool, json_path: ?[]const u8) !void {
    var analysis1 = try analyzer.analyzeTarget(allocator, target, max_bytes, verbose);
    defer analysis1.deinit(allocator);
    var analysis2 = try analyzer.analyzeTarget(allocator, other, max_bytes, verbose);
    defer analysis2.deinit(allocator);

    if (json_path) |path| {
        try reporter.writeDiffJson(path, analysis1, analysis2, false);
        try reporter.writeDiffStdout(analysis1, analysis2, false);
    } else {
        try reporter.writeDiffStdout(analysis1, analysis2, false);
    }
}

fn runFirmwareAnalysis(allocator: Allocator, path: []const u8, max_bytes: usize, verbose: bool, output_html: ?[]const u8, output_md: ?[]const u8) !void {
    const bytes = try std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
    defer allocator.free(bytes);

    var firmware = try firmware_integrity.analyzeFirmware(allocator, bytes, path);
    defer firmware.deinit(allocator);

    const out = std.io.getStdOut().writer();
    try out.print("Firmware Integrity Analysis: {s}\n", .{path});
    try out.print("  Format: {s}\n", .{@tagName(firmware.format)});
    try out.print("  Regions: {}\n", .{firmware.regions.len});
    try out.print("  Integrity Score: {d:.2}%\n", .{firmware.integrity_score});
    try out.print("  Boot Chain Trusted: {}\n", .{firmware.boot_chain_trusted});
    try out.print("  Secure Boot: {}\n", .{firmware.has_secure_boot});
    try out.print("  Rollback Protection: {}\n\n", .{firmware.has_rollback_protection});

    for (firmware.findings) |finding| {
        try out.print("  [!] {s}\n", .{finding.description});
    }

    if (output_html) |html_path| {
        var html_buf: [4096]u8 = undefined;
        var html_stream = std.io.fixedBufferStream(&html_buf);
        const hw = html_stream.writer();
        try hw.print("<html><head><title>Firmware Analysis: {s}</title></head><body>\n", .{path});
        try hw.print("<h1>Firmware Integrity Analysis</h1>\n", .{});
        try hw.print("<p>Format: {s}</p>\n", .{@tagName(firmware.format)});
        try hw.print("<p>Integrity Score: {d:.2}%</p>\n", .{firmware.integrity_score});
        try hw.print("<p>Boot Chain Trusted: {}</p>\n", .{firmware.boot_chain_trusted});
        try hw.print("<h2>Findings</h2><ul>\n", .{});
        for (firmware.findings) |finding| {
            try hw.print("<li>{s}</li>\n", .{finding.description});
        }
        try hw.print("</ul></body></html>\n", .{});
        var html_file = try std.fs.cwd().createFile(html_path, .{ .truncate = true });
        defer html_file.close();
        try html_file.writeAll(html_stream.getWritten());
        if (verbose) try std.io.getStdErr().writer().print("[IntegrityGap] Firmware HTML report: {s}\n", .{html_path});
    }

    if (output_md) |md_path| {
        var md_buf: [4096]u8 = undefined;
        var md_stream = std.io.fixedBufferStream(&md_buf);
        const mw = md_stream.writer();
        try mw.print("# Firmware Integrity Analysis: {s}\n\n", .{path});
        try mw.print("- **Format:** {s}\n", .{@tagName(firmware.format)});
        try mw.print("- **Integrity Score:** {d:.2}%\n", .{firmware.integrity_score});
        try mw.print("- **Boot Chain Trusted:** {}\n", .{firmware.boot_chain_trusted});
        try mw.print("\n## Findings\n\n", .{});
        for (firmware.findings) |finding| {
            try mw.print("- {s}\n", .{finding.description});
        }
        var md_file = try std.fs.cwd().createFile(md_path, .{ .truncate = true });
        defer md_file.close();
        try md_file.writeAll(md_stream.getWritten());
        if (verbose) try std.io.getStdErr().writer().print("[IntegrityGap] Firmware Markdown report: {s}\n", .{md_path});
    }
}

fn runBatchMode(allocator: Allocator, batch_file_path: []const u8, verbose: bool, mode: AnalysisMode, json_path: ?[]const u8, dot_path: ?[]const u8, output_html: ?[]const u8, output_md: ?[]const u8, output_sarif: ?[]const u8, output_csv: ?[]const u8, output_junit: ?[]const u8, fp_red_enabled: bool, enable_remediation: bool, enable_cvss: bool, min_severity: u8, max_findings: ?usize, cache_enabled: bool, cache_directory: ?[]const u8) !void {
    const file = try std.fs.cwd().openFile(batch_file_path, .{});
    defer file.close();
    const reader = file.reader();
    var buf: [4096]u8 = undefined;
    const stderr = std.io.getStdErr().writer();
    var processed: usize = 0;
    var errors: usize = 0;

    while (try reader.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        processed += 1;
        try stderr.print("[IntegrityGap] Batch processing: {s}\n", .{trimmed});
        runFullAnalysis(allocator, trimmed, default_max_bytes, verbose, mode, null, json_path, dot_path, output_html, output_md, output_sarif, output_csv, output_junit, true, fp_red_enabled, enable_remediation, enable_cvss, min_severity, max_findings, cache_enabled, cache_directory) catch |err| {
            errors += 1;
            try stderr.print("[IntegrityGap] Error analyzing {s}: {}\n", .{ trimmed, err });
        };
    }
    if (processed == 0) return error.EmptyBatch;
    if (errors > 0) return error.BatchErrors;
}

fn runReportOnly() !void {
    const stderr = std.io.getStdErr().writer();
    try stderr.writeAll("Report-only mode requires a previous analysis file.\n");
    try stderr.writeAll("Usage: integritygap /path/to/binary --report-only --json /path/to/previous_analysis.json\n");
    try stderr.writeAll("This will re-generate reports from a previous JSON analysis file.\n");
    std.process.exit(1);
}

fn parseComplianceFramework(name: []const u8) compliance_engine.RegulatoryFramework {
    const names = [_]struct { name: []const u8, fw: compliance_engine.RegulatoryFramework }{
        .{ .name = "pci-dss", .fw = .pci_dss },
        .{ .name = "hipaa", .fw = .hipaa },
        .{ .name = "soc2", .fw = .soc2 },
        .{ .name = "iso-27001", .fw = .iso_27001 },
        .{ .name = "gdpr", .fw = .gdpr_technical },
    };
    for (names) |entry| {
        if (std.mem.eql(u8, name, entry.name)) return entry.fw;
    }
    return .pci_dss;
}

fn writeComplianceJsonToWriter(w: anytype, report: compliance_engine.ComplianceReport) !void {
    try w.writeAll("{\n  \"framework\": \"");
    try w.writeAll(@tagName(report.framework));
    try w.print("\",\n  \"score\": {d:.2},\n", .{report.score});
    try w.print("  \"passed\": {}, \"failed\": {}, \"not_applicable\": {}, \"not_checked\": {}, \"partial\": {}\n", .{
        report.passed, report.failed, report.not_applicable, report.not_checked, report.partial,
    });
    try w.writeAll("}\n");
}

fn writeComplianceJson(path: []const u8, report: compliance_engine.ComplianceReport) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeComplianceJsonToWriter(file.writer(), report);
}

fn writeComplianceStdout(report: compliance_engine.ComplianceReport) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Conformidade ===\n", .{});
    try w.print("  Framework: {s}\n", .{@tagName(report.framework)});
    try w.print("  Score: {d:.2}%\n", .{report.score});
    try w.print("  Passed: {} | Failed: {} | N/A: {} | Not Checked: {} | Partial: {}\n", .{
        report.passed, report.failed, report.not_applicable, report.not_checked, report.partial,
    });
    for (report.findings) |finding| {
        if (finding.status == .non_compliant) {
            try w.print("  [FAIL] [{s}] {s}\n", .{ finding.requirement.requirement_id, finding.requirement.description });
        }
    }
}

fn printFirmwareSummary(analysis: firmware_integrity.FirmwareAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Firmware Integrity Analysis ===\n", .{});
    try w.print("  Format: {s} | Score: {d:.2}%\n", .{ @tagName(analysis.format), analysis.integrity_score });
    try w.print("  Boot Chain Trusted: {} | Secure Boot: {}\n", .{ analysis.boot_chain_trusted, analysis.has_secure_boot });
    for (analysis.findings) |f| try w.print("  [FIRMWARE] {s}\n", .{f.description});
}

fn parseSeverity(name: []const u8) u8 {
    if (std.mem.eql(u8, name, "critical")) return 90;
    if (std.mem.eql(u8, name, "high")) return 70;
    if (std.mem.eql(u8, name, "medium")) return 50;
    if (std.mem.eql(u8, name, "low")) return 25;
    if (std.mem.eql(u8, name, "none")) return 0;
    return std.fmt.parseInt(u8, name, 10) catch 0;
}

fn printConcurrencySummary(analysis: concurrency_analyzer.ConcurrencyAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Concurrency Analysis ===\n", .{});
    try w.print("  Detected Races: {} | Threading Issues: {} | Concurrency Risk Score: {d:.2}\n", .{ analysis.race_conditions.len, analysis.threading_issues.len, analysis.concurrency_gap_score });
    for (analysis.race_conditions) |rc| try w.print("  [RACE] 0x{x}: {s}\n", .{ rc.address, rc.description });
    for (analysis.threading_issues) |ti| try w.print("  [ISSUE] {s}\n", .{ti.description});
}

fn printTaintSummary(analysis: taint_analyzer.TaintAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Taint Analysis ===\n", .{});
    try w.print("  Sources: {} | Sinks: {} | Score: {d:.2}\n", .{ analysis.sources.len, analysis.sinks.len, analysis.taint_gap_score });
    for (analysis.propagations) |p| {
        if (!p.sanitized) try w.print("  [TAINT] {s}\n", .{p.description});
    }
}

fn printCryptoSummary(analysis: crypto_auditor.CryptoAudit) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Cryptographic Audit ===\n", .{});
    try w.print("  Usages: {} | Weak: {} | Hardcoded Keys: {} | Score: {d:.2}\n", .{
        analysis.cipher_usages.len, analysis.weak_cipher_count, analysis.hardcoded_key_count, analysis.crypto_gap_score,
    });
    for (analysis.findings) |f| try w.print("  [CRYPTO] {s}\n", .{f.description});
}

fn printPrivacySummary(analysis: privacy_analyzer.PrivacyAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Privacidade ===\n", .{});
    try w.print("  Findings: {} | PII Points: {} | GDPR: {d:.1}% | CCPA: {d:.1}% | Score: {d:.2}\n", .{
        analysis.findings.len, analysis.pii_collection_points, analysis.gdpr_compliance_score, analysis.ccpa_compliance_score, analysis.privacy_gap_score,
    });
    for (analysis.findings) |f| try w.print("  [PRIVACY] {s}\n", .{f.description});
}

fn printComplianceSummary(analysis: compliance_engine.ComplianceSuite) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Conformidade ===\n", .{});
    try w.print("  Overall: {d:.1}% | Critical: {} | High: {} | Medium: {}\n", .{
        analysis.overall_score, analysis.critical_findings, analysis.high_findings, analysis.medium_findings,
    });
    for (analysis.reports) |r| {
        try w.print("  [{s}] Score: {d:.1}% Passed: {} Failed: {} Partial: {}\n", .{
            @tagName(r.framework), r.score, r.passed, r.failed, r.partial,
        });
    }
}

fn printMemorySummary(analysis: memory_safety.BinarySafetyAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Memoria ===\n", .{});
    try w.print("  Unsafe Copies: {} | Format Strings: {} | Leaks: {} | Score: {d:.2}\n", .{
        analysis.unsafe_copy_count, analysis.format_string_count, analysis.memory_leak_count, analysis.safety_gap_score,
    });
    for (analysis.findings) |f| try w.print("  [MEM] CWE-{}: {s}\n", .{ f.cwe_id, f.description });
}

fn printDependencySummary(analysis: dependency_checker.DependencyAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Dependencias ===\n", .{});
    try w.print("  Total: {} | Vulnerable: {} | Score: {d:.2}\n", .{
        analysis.total_dependencies, analysis.vulnerable_count, analysis.supply_chain_score,
    });
    for (analysis.findings) |f| {
        try w.print("  [DEP] {s}", .{f.description});
        if (f.cve_id.len > 0) try w.print(" ({s})", .{f.cve_id});
        try w.writeByte('\n');
    }
}

fn printConfigSummary(analysis: config_auditor.ConfigAudit) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== Configuracao ===\n", .{});
    try w.print("  Credentials: {} | Insecure Defaults: {} | Score: {d:.2}\n", .{
        analysis.hardcoded_credentials, analysis.insecure_defaults, analysis.config_security_score,
    });
    for (analysis.findings) |f| try w.print("  [CONFIG] {s}\n", .{f.description});
}

fn printStringSummary(analysis: string_analyzer.StringAnalysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=== String Analysis ===\n", .{});
    try w.print("  Total Strings Extracted: {} | Interesting: {} ({d:.1}%)\n", .{
        analysis.total_strings, analysis.findings.len, analysis.interesting_ratio,
    });
    try w.print("  URLs: {} | IPs: {} | Emails: {} | Paths: {}\n", .{
        analysis.url_count, analysis.ip_count, analysis.email_count, analysis.path_count,
    });
    try w.print("  Registry Keys: {} | Shell Commands: {} | Crypto Keys: {} | JWTs: {} | Base64: {}\n", .{
        analysis.registry_count, analysis.shell_count, analysis.crypto_key_count, analysis.jwt_count, analysis.base64_count,
    });
    for (analysis.findings) |f| {
        const class_name = @tagName(f.classification);
        try w.print("  [{s}] 0x{x}: {s}\n", .{ class_name, f.offset, f.value });
    }
}

fn printReportSummary(report: report_engine.Report, analysis: types.Analysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("\n=================================================================\n", .{});
    try w.print("  IntegrityGap Comprehensive Security Report\n", .{});
    try w.print("  Target: {s}\n", .{report.target_path});
    try w.print("  Threat Classification: {s}\n", .{@tagName(analysis.summary.threat)});
    try w.print("  Overall Score: {d:.1}% (higher is better)\n", .{report.overall_score});
    try w.print("  Findings: {} (Critical: {}, High: {}, Medium: {}, Low: {})\n", .{
        report.total_findings, report.critical_count, report.high_count, report.medium_count, report.low_count,
    });
    try w.print("  Integrity Gap: {d:.2} (lower is better)\n", .{analysis.summary.aggregate_gap});
    try w.print("=================================================================\n", .{});
}

fn printUsage() void {
    const out = std.io.getStdOut().writer();
    out.writeAll(
        \\IntegrityGap - Commercial-Grade Binary Integrity Analysis Suite v2.1.0
        \\
        \\USAGE:
        \\  IntegrityGap <target> [options]
        \\
        \\ANALYSIS MODES (standalone flags or --mode <mode>):
        \\  --all                  All engines enabled (default)
        \\  --integrity-gap        Core 10-dimension scoring only
        \\  --concurrency          Concurrency analysis engine
        \\  --taint                Taint propagation analysis
        \\  --firmware             Firmware image analysis
        \\  --crypto               Cryptographic audit
        \\  --privacy              Privacy compliance analysis
        \\  --compliance           Regulatory compliance checks
        \\  --memory               Memory safety analysis
        \\  --dependencies         Dependency/CVE scanning
        \\  --config               Configuration audit
        \\  --strings              String extraction and classification
        \\
        \\OUTPUT OPTIONS:
        \\  --target <path>        Binary target (PE/ELF/Mach-O)
        \\  --json <path>          JSON output
        \\  --plain                Human-readable plaintext output
        \\  --dot <path>           DOT graph of functions and gaps
        \\  --html <path>          Comprehensive HTML report
        \\  --markdown <path>      Comprehensive Markdown report
        \\  --sarif <path>         SARIF-compatible output
        \\  --csv <path>           CSV output of evidence
        \\  --junit <path>         JUnit XML output
        \\
        \\COMPARISON OPTIONS:
        \\  --diff <path>          Compare against another binary
        \\  --baseline <path>      Compare against known-clean baseline
        \\
        \\COMPLIANCE OPTIONS:
        \\  --compliance-framework <fw>  Run compliance check: pci-dss, hipaa, soc2, iso-27001
        \\
        \\POST-PROCESSING OPTIONS:
        \\  --fp-reduction         Enable false positive reduction
        \\  --enable-remediation   Enable remediation suggestions
        \\  --enable-cvss          Enable CVSS scoring
        \\
        \\CACHE OPTIONS:
        \\  --cache-enabled        Enable result caching (default: enabled)
        \\  --cache-directory <d>  Cache storage directory
        \\
        \\FILTER OPTIONS:
        \\  --min-severity <lvl>   Minimum severity: none, low, medium, high, critical
        \\  --max-findings <N>     Maximum findings to report
        \\
        \\CONFIG OPTIONS:
        \\  --config-file <path>   Load configuration from file
        \\
        \\BATCH OPTIONS:
        \\  --batch <file>         Batch process files listed in <file>
        \\  --baseline-dir <dir>   Baseline directory for batch comparison
        \\
        \\ADDITIONAL OPTIONS:
        \\  --max-bytes <N>        Read limit (default: 268435456)
        \\  --verbose, -v          Verbose progress logs
        \\  --version              Show version information
        \\  --help, -h             This help text
        \\
    ) catch {};
}

fn filterEvidenceBySeverity(allocator: Allocator, evidence: []const types.Evidence, profiles: []types.FunctionProfile, min_severity: u8, max_findings: ?usize) ![]types.Evidence {
    if (min_severity == 0 and max_findings == null) return @constCast(evidence);

    var new_evidence = std.ArrayList(types.Evidence).init(allocator);
    errdefer new_evidence.deinit();

    var old_to_new = std.AutoHashMap(usize, usize).init(allocator);
    defer old_to_new.deinit();

    for (evidence, 0..) |ev, i| {
        if (ev.severity >= min_severity) {
            try old_to_new.put(i, new_evidence.items.len);
            try new_evidence.append(ev);
        }
    }

    for (profiles) |*p| {
        var new_start: ?usize = null;
        var new_count: usize = 0;
        const end = p.evidence_start + p.evidence_count;
        var old_i = p.evidence_start;
        while (old_i < end) : (old_i += 1) {
            if (old_to_new.get(old_i)) |new_idx| {
                if (new_start == null) new_start = new_idx;
                new_count += 1;
            }
        }
        p.evidence_start = new_start orelse 0;
        p.evidence_count = new_count;
    }

    if (max_findings) |max| {
        if (new_evidence.items.len > max) {
            new_evidence.shrinkAndFree(max);
            for (profiles) |*p| {
                if (p.evidence_start >= max) {
                    p.evidence_start = 0;
                    p.evidence_count = 0;
                } else if (p.evidence_start + p.evidence_count > max) {
                    p.evidence_count = max - p.evidence_start;
                }
            }
        }
    }

    return new_evidence.items;
}
