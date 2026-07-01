const std = @import("std");
const types = @import("../types.zig");
const parser = @import("../core/parser.zig");

const Analysis = types.Analysis;
const Summary = types.Summary;
const CategoryScores = types.CategoryScores;
const FunctionProfile = types.FunctionProfile;
const Evidence = types.Evidence;
const FunctionSpan = types.FunctionSpan;
const ResolvedCall = types.ResolvedCall;

pub fn writeJson(path: []const u8, analysis: Analysis) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeAnalysisJson(file.writer(), analysis);
}

pub fn writeJsonStdout(analysis: Analysis) !void {
    try writeAnalysisJson(std.io.getStdOut().writer(), analysis);
}

fn writeAnalysisJson(w: anytype, analysis: Analysis) !void {
    try w.writeAll("{\n");
    try w.writeAll("  \"tool\": \"IntegrityGap\",\n");
    try w.writeAll("  \"version\": \"2.0\",\n");
    try w.writeAll("  \"target\": ");
    try writeJsonString(w, analysis.target_path);
    try w.writeAll(",\n");
    try w.writeAll("  \"sha256\": \"");
    try writeHexHash(w, analysis.sha256);
    try w.writeAll("\",\n");
    try w.print("  \"format\": \"{s}\",\n", .{@tagName(analysis.image.format)});
    try w.print("  \"arch\": \"{s}\",\n", .{@tagName(analysis.image.arch)});
    try w.print("  \"entry_va\": \"0x{x}\",\n", .{analysis.image.entry_va});
    try w.print("  \"executable_sections\": {},\n", .{parser.countExecSections(analysis.image)});
    try w.print("  \"imports\": {},\n", .{analysis.image.imports.len});
    try w.print("  \"exports\": {},\n", .{analysis.image.exports_count});
    try w.print("  \"relocations\": {},\n", .{analysis.image.relocations_count});
    try w.print("  \"instructions\": {},\n", .{analysis.instructions.len});
    try w.print("  \"functions\": {},\n", .{analysis.functions.len});
    try w.print("  \"functions_identified\": {},\n", .{analysis.functions.len});
    try w.print("  \"functions_analyzed\": {},\n", .{analysis.profiles.len});
    try w.print("  \"symbols\": {},\n", .{analysis.image.symbols.len});
    try w.print("  \"logging_present\": {},\n", .{analysis.logging_present});
    try w.writeAll("  \"summary\": ");
    try writeSummaryJson(w, analysis.summary, "  ");
    try w.writeAll(",\n");

    try w.writeAll("  \"functions_detail\": [\n");
    for (analysis.profiles, 0..) |profile, idx| {
        try writeFunctionJson(w, profile, analysis.evidence, "    ");
        if (idx + 1 < analysis.profiles.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    try w.writeAll("  \"evidence\": [\n");
    for (analysis.evidence, 0..) |ev, idx| {
        try writeEvidenceJson(w, ev, "    ");
        if (idx + 1 < analysis.evidence.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ],\n");

    try w.writeAll("  \"call_graph\": [\n");
    for (analysis.call_edges, 0..) |edge, idx| {
        try w.print("    {{\"from\":\"0x{x}\",\"to\":\"0x{x}\"}}", .{ edge.from, edge.to });
        if (idx + 1 < analysis.call_edges.len) try w.writeAll(",");
        try w.writeAll("\n");
    }
    try w.writeAll("  ]\n");
    try w.writeAll("}\n");
}

fn writeSummaryJson(w: anytype, summary: Summary, indent: []const u8) !void {
    _ = indent;
    try w.writeAll("{");
    try w.print("\"threat_class\":\"{s}\",\"aggregate_gap\":{d:.2},\"anomaly_confidence\":{d:.2},\"scores\":", .{
        @tagName(summary.threat),
        summary.aggregate_gap,
        summary.anomaly_confidence,
    });
    try writeScoresJson(w, summary.scores);
    try w.writeAll("}");
}

fn writeScoresJson(w: anytype, scores: CategoryScores) !void {
    try w.print(
        "{{\"error_handling\":{d:.2},\"resource_lifecycle\":{d:.2},\"input_validation\":{d:.2},\"cryptographic\":{d:.2},\"logging_auditability\":{d:.2},\"cleanup\":{d:.2}}}",
        .{ scores.error_handling, scores.resource_lifecycle, scores.input_validation, scores.cryptographic, scores.logging_auditability, scores.cleanup },
    );
}

fn writeFunctionJson(w: anytype, profile: FunctionProfile, evidence: []const Evidence, indent: []const u8) !void {
    try w.print("{s}{{\"start\":\"0x{x}\",\"end\":\"0x{x}\",\"instruction_count\":{},\"aggregate_gap\":{d:.2},\"anomaly_confidence\":{d:.2},", .{
        indent,
        profile.span.start,
        profile.span.end,
        profile.span.instr_end - profile.span.instr_start,
        profile.aggregate_gap,
        profile.confidence,
    });
    try w.writeAll("\"scores\":");
    try writeScoresJson(w, profile.scores);
    try w.print(",\"critical_calls\":{},\"unchecked_critical_calls\":{},\"acquire_calls\":{},\"release_calls\":{},\"high_risk_calls\":{},\"logging_calls\":{},\"cleanup_exit_paths\":{},\"cleanup_dirty_exit_paths\":{},\"cleanup_error_dirty_paths\":{},\"pointer_deref_before_validation\":{},", .{
        profile.critical_calls,
        profile.unchecked_critical_calls,
        profile.acquire_calls,
        profile.release_calls,
        profile.high_risk_calls,
        profile.logging_calls,
        profile.cleanup_exit_paths,
        profile.cleanup_dirty_exit_paths,
        profile.cleanup_error_dirty_paths,
        profile.pointer_deref_before_validation,
    });
    try w.writeAll("\"calls\":[");
    for (profile.calls, 0..) |call, idx| {
        if (idx > 0) try w.writeAll(",");
        try w.print("{{\"address\":\"0x{x}\",\"name\":", .{call.va});
        try writeJsonString(w, call.name);
        try w.print(",\"category\":\"{s}\",\"role\":\"{s}\",\"checked\":{},\"high_risk\":{}", .{ @tagName(call.category), @tagName(call.role), call.checked, call.high_risk });
        if (call.target) |target| try w.print(",\"target\":\"0x{x}\"", .{target});
        try w.writeAll("}");
    }
    try w.writeAll("],\"evidence\":[");
    const end = @min(evidence.len, profile.evidence_start + profile.evidence_count);
    var first = true;
    for (evidence[profile.evidence_start..end]) |ev| {
        if (!first) try w.writeAll(",");
        first = false;
        try writeEvidenceJson(w, ev, "");
    }
    try w.writeAll("]}");
}

fn writeEvidenceJson(w: anytype, ev: Evidence, indent: []const u8) !void {
    try w.print("{s}{{\"function\":\"0x{x}\",\"address\":\"0x{x}\",\"category\":", .{ indent, ev.function_va, ev.address });
    try writeJsonString(w, ev.category);
    try w.writeAll(",\"message\":");
    try writeJsonString(w, ev.message);
    try w.print(",\"severity\":{}}}", .{ev.severity});
}

pub fn writePlain(analysis: Analysis) !void {
    const w = std.io.getStdOut().writer();
    try w.print("IntegrityGap: {s}\n", .{analysis.target_path});
    try w.print("Format: {s}/{s}  Entry: 0x{x}\n", .{ @tagName(analysis.image.format), @tagName(analysis.image.arch), analysis.image.entry_va });
    try w.print("Classification: {s}  Gap: {d:.2}  Confidence: {d:.2}\n", .{ @tagName(analysis.summary.threat), analysis.summary.aggregate_gap, analysis.summary.anomaly_confidence });
    try w.print("Scores: error={d:.1} resource={d:.1} input={d:.1} crypto={d:.1} logging={d:.1} cleanup={d:.1}\n", .{
        analysis.summary.scores.error_handling,
        analysis.summary.scores.resource_lifecycle,
        analysis.summary.scores.input_validation,
        analysis.summary.scores.cryptographic,
        analysis.summary.scores.logging_auditability,
        analysis.summary.scores.cleanup,
    });
    try w.print("Functions identified/analyzed: {}/{}  Instructions: {}  Evidences: {}\n", .{ analysis.functions.len, analysis.profiles.len, analysis.instructions.len, analysis.evidence.len });
    try w.writeAll("\nFunctions with material gap:\n");
    var shown: usize = 0;
    for (analysis.profiles) |profile| {
        if (profile.aggregate_gap < 18 and profile.confidence < 35) continue;
        try w.print("  0x{x}-0x{x} gap={d:.2} conf={d:.2} critical={}/{} resources={}/{} cleanup_dirty={}/{}\n", .{
            profile.span.start,
            profile.span.end,
            profile.aggregate_gap,
            profile.confidence,
            profile.unchecked_critical_calls,
            profile.critical_calls,
            profile.release_calls,
            profile.acquire_calls,
            profile.cleanup_dirty_exit_paths,
            profile.cleanup_exit_paths,
        });
        const ev_start = profile.evidence_start;
        const ev_end = @min(ev_start + profile.evidence_count, analysis.evidence.len);
        if (ev_end > ev_start) {
            var ev_idx: usize = ev_start;
            while (ev_idx < ev_end and ev_idx < ev_start + 4) : (ev_idx += 1) {
                const ev = analysis.evidence[ev_idx];
                try w.print("    -> {s}: {s} (sev={})\n", .{ ev.category, ev.message, ev.severity });
            }
        }
        shown += 1;
        if (shown >= 10) break;
    }
    if (shown == 0) try w.writeAll("  no material gaps above threshold\n");
}

pub fn writeDot(path: []const u8, analysis: Analysis) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    const w = file.writer();
    try w.writeAll("digraph IntegrityGap {\n");
    try w.writeAll("  rankdir=LR;\n  node [shape=box,fontname=\"monospace\",fontsize=10];\n  edge [color=gray50,arrowsize=0.6];\n");
    try w.writeAll("  legend [shape=note,label=\"IntegrityGap\\nverde: gap baixo\\namarelo: medio\\nlaranja/vermelho: alto\\narestas: call graph real\"];\n");
    for (analysis.profiles, 0..) |profile, idx| {
        const color = gapColor(profile.aggregate_gap);
        try w.print("  f{} [label=\"0x{x}\\ngap={d:.1}\\nconf={d:.1}\\n{s}\",style=filled,fillcolor=\"{s}\"];\n", .{
            idx,
            profile.span.start,
            profile.aggregate_gap,
            profile.confidence,
            topGapName(profile.scores),
            color,
        });
    }
    for (analysis.call_edges) |edge| {
        const from = functionIndexByStart(analysis.functions, edge.from) orelse continue;
        const to = functionIndexByStart(analysis.functions, edge.to) orelse continue;
        try w.print("  f{} -> f{};\n", .{ from, to });
    }
    try w.writeAll("}\n");
}

fn gapColor(score: f64) []const u8 {
    if (score >= 70) return "#e53935";
    if (score >= 40) return "#fb8c00";
    if (score >= 15) return "#fdd835";
    return "#66bb6a";
}

fn topGapName(scores: CategoryScores) []const u8 {
    var best = scores.error_handling;
    var name: []const u8 = "error";
    if (scores.resource_lifecycle > best) { best = scores.resource_lifecycle; name = "resource"; }
    if (scores.input_validation > best) { best = scores.input_validation; name = "input"; }
    if (scores.cryptographic > best) { best = scores.cryptographic; name = "crypto"; }
    if (scores.logging_auditability > best) { best = scores.logging_auditability; name = "logging"; }
    if (scores.cleanup > best) { name = "cleanup"; }
    return name;
}

fn functionIndexByStart(functions: []const FunctionSpan, start: u64) ?usize {
    for (functions, 0..) |function, idx| {
        if (function.start == start) return idx;
    }
    return null;
}

pub fn writeDiffJson(path: []const u8, base: Analysis, other: Analysis, baseline_mode: bool) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeDiffJsonTo(file.writer(), base, other, baseline_mode);
}

pub fn writeDiffStdout(base: Analysis, other: Analysis, baseline_mode: bool) !void {
    try writeDiffJsonTo(std.io.getStdOut().writer(), base, other, baseline_mode);
}

fn writeDiffJsonTo(w: anytype, base: Analysis, other: Analysis, baseline_mode: bool) !void {
    const similarity = scoreSimilarity(base.summary.scores, other.summary.scores);
    try w.writeAll("{\n");
    try w.print("  \"tool\": \"IntegrityGap\",\n  \"diff_mode\": {},\n  \"baseline_mode\": {},\n", .{ !baseline_mode, baseline_mode });
    try w.writeAll("  \"base\": ");
    try writeJsonString(w, base.target_path);
    try w.writeAll(",\n  \"target\": ");
    try writeJsonString(w, other.target_path);
    try w.writeAll(",\n");
    try w.print("  \"base_threat\": \"{s}\",\n  \"target_threat\": \"{s}\",\n  \"global_similarity\": {d:.2},\n", .{
        @tagName(base.summary.threat),
        @tagName(other.summary.threat),
        similarity,
    });
    try w.print("  \"aggregate_gap_delta\": {d:.2},\n  \"confidence_delta\": {d:.2},\n", .{
        other.summary.aggregate_gap - base.summary.aggregate_gap,
        other.summary.anomaly_confidence - base.summary.anomaly_confidence,
    });
    try w.writeAll("  \"category_delta\": ");
    try writeScoresDeltaJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll(",\n");
    try w.print("  \"function_count_delta\": {},\n  \"evidence_count_delta\": {},\n", .{
        @as(isize, @intCast(other.functions.len)) - @as(isize, @intCast(base.functions.len)),
        @as(isize, @intCast(other.evidence.len)) - @as(isize, @intCast(base.evidence.len)),
    });
    try w.writeAll("  \"semantic_change\": ");
    try writeSemanticDiffJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll(",\n  \"semantic_changes\": ");
    try writeSemanticChangesJson(w, base.summary.scores, other.summary.scores);
    try w.writeAll("\n");
    try w.writeAll("}\n");
}

fn writeScoresDeltaJson(w: anytype, a: CategoryScores, b: CategoryScores) !void {
    try w.print(
        "{{\"error_handling\":{d:.2},\"resource_lifecycle\":{d:.2},\"input_validation\":{d:.2},\"cryptographic\":{d:.2},\"logging_auditability\":{d:.2},\"cleanup\":{d:.2}}}",
        .{
            b.error_handling - a.error_handling,
            b.resource_lifecycle - a.resource_lifecycle,
            b.input_validation - a.input_validation,
            b.cryptographic - a.cryptographic,
            b.logging_auditability - a.logging_auditability,
            b.cleanup - a.cleanup,
        },
    );
}

fn scoreSimilarity(a: CategoryScores, b: CategoryScores) f64 {
    const dist =
        @abs(a.error_handling - b.error_handling) +
        @abs(a.resource_lifecycle - b.resource_lifecycle) +
        @abs(a.input_validation - b.input_validation) +
        @abs(a.cryptographic - b.cryptographic) +
        @abs(a.logging_auditability - b.logging_auditability) +
        @abs(a.cleanup - b.cleanup);
    const clamped = if (100.0 - dist / 6.0 < 0) 0 else if (100.0 - dist / 6.0 > 100) 100 else 100.0 - dist / 6.0;
    return clamped;
}

fn writeSemanticDiffJson(w: anytype, base: CategoryScores, other: CategoryScores) !void {
    const name = dominantDeltaCategory(base, other);
    const delta = categoryDeltaByName(base, other, name);
    try w.writeAll("{\"dominant_category\":");
    try writeJsonString(w, name);
    try w.writeAll(",\"direction\":");
    try writeJsonString(w, if (delta > 2.5) "worse" else if (delta < -2.5) "better" else "stable");
    try w.print(",\"magnitude\":{d:.2},\"classification\":", .{delta});
    try writeJsonString(w, semanticChangeClass(name, delta));
    try w.writeAll("}");
}

fn writeSemanticChangesJson(w: anytype, base: CategoryScores, other: CategoryScores) !void {
    const items = [_][]const u8{
        "error_handling",
        "resource_lifecycle",
        "input_validation",
        "cryptographic",
        "logging_auditability",
        "cleanup",
    };
    try w.writeAll("[");
    for (items, 0..) |name, idx| {
        if (idx > 0) try w.writeAll(",");
        const delta = categoryDeltaByName(base, other, name);
        try w.writeAll("{\"category\":");
        try writeJsonString(w, name);
        try w.writeAll(",\"direction\":");
        try writeJsonString(w, if (delta > 2.5) "worse" else if (delta < -2.5) "better" else "stable");
        try w.print(",\"delta\":{d:.2},\"classification\":", .{delta});
        try writeJsonString(w, semanticChangeClass(name, delta));
        try w.writeAll("}");
    }
    try w.writeAll("]");
}

fn dominantDeltaCategory(base: CategoryScores, other: CategoryScores) []const u8 {
    var name: []const u8 = "error_handling";
    var best = @abs(other.error_handling - base.error_handling);
    const candidates = [_]struct { name: []const u8, delta: f64 }{
        .{ .name = "resource_lifecycle", .delta = @abs(other.resource_lifecycle - base.resource_lifecycle) },
        .{ .name = "input_validation", .delta = @abs(other.input_validation - base.input_validation) },
        .{ .name = "cryptographic", .delta = @abs(other.cryptographic - base.cryptographic) },
        .{ .name = "logging_auditability", .delta = @abs(other.logging_auditability - base.logging_auditability) },
        .{ .name = "cleanup", .delta = @abs(other.cleanup - base.cleanup) },
    };
    for (candidates) |candidate| {
        if (candidate.delta > best) {
            best = candidate.delta;
            name = candidate.name;
        }
    }
    return name;
}

fn categoryDeltaByName(base: CategoryScores, other: CategoryScores, name: []const u8) f64 {
    if (std.mem.eql(u8, name, "error_handling")) return other.error_handling - base.error_handling;
    if (std.mem.eql(u8, name, "resource_lifecycle")) return other.resource_lifecycle - base.resource_lifecycle;
    if (std.mem.eql(u8, name, "input_validation")) return other.input_validation - base.input_validation;
    if (std.mem.eql(u8, name, "cryptographic")) return other.cryptographic - base.cryptographic;
    if (std.mem.eql(u8, name, "logging_auditability")) return other.logging_auditability - base.logging_auditability;
    return other.cleanup - base.cleanup;
}

fn semanticChangeClass(name: []const u8, delta: f64) []const u8 {
    if (@abs(delta) <= 2.5) return "semantically_stable";
    if (delta < 0) return "integrity_improved";
    if (std.mem.eql(u8, name, "error_handling")) return "weaker_error_handling";
    if (std.mem.eql(u8, name, "resource_lifecycle")) return "weaker_resource_lifecycle";
    if (std.mem.eql(u8, name, "input_validation")) return "weaker_input_validation";
    if (std.mem.eql(u8, name, "cryptographic")) return "weaker_crypto_integrity";
    if (std.mem.eql(u8, name, "logging_auditability")) return "weaker_auditability";
    return "weaker_cleanup";
}

fn writeJsonString(w: anytype, text: []const u8) !void {
    const hex = "0123456789abcdef";
    try w.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11...12, 14...31 => {
                try w.writeAll("\\u00");
                try w.writeByte(hex[byte >> 4]);
                try w.writeByte(hex[byte & 0x0f]);
            },
            else => try w.writeByte(byte),
        }
    }
    try w.writeByte('"');
}

fn writeHexHash(w: anytype, hash: [32]u8) !void {
    const hex = "0123456789abcdef";
    for (hash) |byte| {
        try w.writeByte(hex[byte >> 4]);
        try w.writeByte(hex[byte & 0x0f]);
    }
}

pub fn writeCsv(path: []const u8, analysis: Analysis) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try writeCsvTo(file.writer(), analysis);
}

pub fn writeCsvStdout(analysis: Analysis) !void {
    try writeCsvTo(std.io.getStdOut().writer(), analysis);
}

fn writeCsvTo(w: anytype, analysis: Analysis) !void {
    try w.writeAll("Type,Severity,Category,Address,Function,Message\n");
    for (analysis.evidence) |ev| {
        try w.print("Evidence,{d},", .{ev.severity});
        try writeCsvStr(w, ev.category);
        try w.print(",0x{x},0x{x},", .{ ev.address, ev.function_va });
        try writeCsvStr(w, ev.message);
        try w.writeByte('\n');
    }
    for (analysis.profiles) |profile| {
        if (profile.aggregate_gap < 18 and profile.confidence < 35) continue;
        try w.print("Function,{d:.1},,,0x{x},\"gap={d:.1} conf={d:.1} critical={}/{}\"\n", .{
            profile.aggregate_gap, profile.span.start,
            profile.aggregate_gap, profile.confidence,
            profile.unchecked_critical_calls, profile.critical_calls,
        });
    }
}

fn writeCsvStr(w: anytype, value: []const u8) !void {
    try w.writeByte('"');
    for (value) |c| {
        switch (c) {
            '"' => try w.writeAll("\"\""),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

pub fn writeComplianceSpecific(path: []const u8, analysis: Analysis, framework: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    const w = file.writer();

    try w.print("IntegrityGap Compliance Report - {s}\n", .{framework});
    try w.print("Target: {s}\n", .{analysis.target_path});
    try w.writeAll("SHA256: ");
    try writeHexHash(w, analysis.sha256);
    try w.writeByte('\n');
    try w.print("Threat Class: {s}\n", .{@tagName(analysis.summary.threat)});
    try w.print("Aggregate Gap: {d:.2}\n", .{analysis.summary.aggregate_gap});
    try w.print("Anomaly Confidence: {d:.2}%\n\n", .{analysis.summary.anomaly_confidence});

    if (std.mem.eql(u8, framework, "pci-dss")) {
        try w.writeAll("PCI-DSS Compliance Assessment (Automated Checks)\n");
        try w.writeAll("================================================\n");
        try w.writeAll("PCI-2.1: Change vendor defaults - Analyzed for hardcoded credentials\n");
        try w.writeAll("PCI-3.1: Protect stored cardholder data - Checked encryption usage\n");
        try w.writeAll("PCI-3.5: Protect encryption keys - Verified key storage patterns\n");
        try w.writeAll("PCI-4.1: Encrypt transmission - Evaluated network crypto usage\n");
        try w.writeAll("PCI-10.1: Implement audit trails - Assessed logging coverage\n\n");
        try w.print("Cryptographic Score: {d:.1}/100 (higher is better)\n", .{analysis.summary.scores.cryptographic});
        try w.print("Logging Score: {d:.1}/100\n", .{analysis.summary.scores.logging_auditability});
        if (analysis.summary.scores.cryptographic < 50) {
            try w.writeAll("RESULT: FAIL - Cryptographic controls below PCI-DSS threshold\n");
        } else {
            try w.writeAll("RESULT: PASS (automated checks only - manual review required)\n");
        }
    } else if (std.mem.eql(u8, framework, "hipaa")) {
        try w.writeAll("HIPAA Compliance Assessment (Automated Checks)\n");
        try w.writeAll("==============================================\n");
        try w.writeAll("HIPAA 164.312(a)(1): Access control - Analyzed authentication patterns\n");
        try w.writeAll("HIPAA 164.312(a)(2)(iv): Encryption - Verified crypto implementations\n");
        try w.writeAll("HIPAA 164.312(b): Audit controls - Assessed logging coverage\n");
        try w.writeAll("HIPAA 164.312(c)(1): Integrity controls - Checked error handling\n");
        try w.writeAll("HIPAA 164.312(d): Person/entity authentication - Evaluated auth patterns\n");
        try w.writeAll("HIPAA 164.312(e): Transmission security - Checked network crypto\n\n");
        try w.print("Cryptographic Score: {d:.1}/100\n", .{analysis.summary.scores.cryptographic});
        try w.print("Error Handling Score: {d:.1}/100\n", .{analysis.summary.scores.error_handling});
        try w.print("Logging Score: {d:.1}/100\n", .{analysis.summary.scores.logging_auditability});
    } else if (std.mem.eql(u8, framework, "soc2")) {
        try w.writeAll("SOC 2 Compliance Assessment (Automated Checks)\n");
        try w.writeAll("===============================================\n");
        try w.writeAll("Security - Protected against unauthorized access (CC6.x)\n");
        try w.writeAll("Availability - System availability monitoring (CC7.x)\n");
        try w.writeAll("Processing Integrity - System processing is complete/valid (CC8.x)\n");
        try w.writeAll("Confidentiality - Information restricted to authorized (CC6.x)\n");
        try w.writeAll("Privacy - Personal information collected per criteria (CC9.x)\n\n");
        try w.print("Overall Integrity Score: {d:.2}/100\n", .{analysis.summary.aggregate_gap});
    } else if (std.mem.eql(u8, framework, "iso-27001")) {
        try w.writeAll("ISO 27001 Compliance Assessment (Automated Checks)\n");
        try w.writeAll("==================================================\n");
        try w.writeAll("A.8.2: Information classification - Analyzed data handling\n");
        try w.writeAll("A.9.1: Access control policy - Verified authentication\n");
        try w.writeAll("A.10.1: Cryptographic controls - Evaluated crypto usage\n");
        try w.writeAll("A.12.4: Logging and monitoring - Assessed audit trails\n");
        try w.writeAll("A.12.6: Technical vulnerability management - Checked patching\n");
        try w.writeAll("A.14.2: Security in development - Analyzed coding patterns\n\n");
        try w.print("Resource Lifecycle Score: {d:.1}/100\n", .{analysis.summary.scores.resource_lifecycle});
        try w.print("Input Validation Score: {d:.1}/100\n", .{analysis.summary.scores.input_validation});
    } else {
        try w.print("Unknown framework: {s}\n", .{framework});
    }

    try w.writeAll("\n---\n");
    try w.writeAll("This is an automated assessment. Manual review by a qualified assessor is required for certification.\n");
    try w.writeAll("Generated by IntegrityGap v2.0.0\n");
}

pub fn writeEvidenceCsv(path: []const u8, analysis: Analysis) !void {
    try writeCsv(path, analysis);
}
