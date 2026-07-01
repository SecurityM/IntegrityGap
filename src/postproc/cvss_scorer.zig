const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub const CvssVersion = enum { v3_1, v3_0, v2_0 };

pub const AttackComplexity = enum { low, high };
pub const PrivilegesRequired = enum { none, low, high };
pub const UserInteraction = enum { none, required };
pub const Scope = enum { unchanged, changed };
pub const ConfidentialityImpact = enum { none, low, high };
pub const IntegrityImpact = enum { none, low, high };
pub const AvailabilityImpact = enum { none, low, high };
pub const ExploitCodeMaturity = enum { not_defined, unproven, proof_of_concept, functional, high };
pub const RemediationLevel = enum { not_defined, official_fix, temporary_fix, workaround, unavailable };
pub const ReportConfidence = enum { not_defined, unknown, reasonable, confirmed };
pub const Severity = enum { none, low, medium, high, critical };

pub const CvssVector = struct {
    version: CvssVersion = .v3_1,
    attack_vector: AttackVector = .network,
    attack_complexity: AttackComplexity = .low,
    privileges_required: PrivilegesRequired = .none,
    user_interaction: UserInteraction = .none,
    scope: Scope = .unchanged,
    confidentiality: ConfidentialityImpact = .none,
    integrity: IntegrityImpact = .none,
    availability: AvailabilityImpact = .none,
    exploit_code_maturity: ExploitCodeMaturity = .not_defined,
    remediation_level: RemediationLevel = .not_defined,
    report_confidence: ReportConfidence = .not_defined,
    environmental_confidentiality: ConfidentialityImpact = .none,
    environmental_integrity: IntegrityImpact = .none,
    environmental_availability: AvailabilityImpact = .none,
};

pub const AttackVector = enum {
    network,
    adjacent_network,
    local,
    physical,
};

pub const CvssScore = struct {
    base_score: f64,
    temporal_score: f64,
    environmental_score: f64,
    overall_score: f64,
    severity: Severity,
    vector_string: []const u8,
};

fn severityFromScore(score: f64) Severity {
    if (score >= 9.0) return .critical;
    if (score >= 7.0) return .high;
    if (score >= 4.0) return .medium;
    if (score >= 0.1) return .low;
    return .none;
}

fn avValue(av: AttackVector) f64 {
    return switch (av) {
        .network => 0.85,
        .adjacent_network => 0.62,
        .local => 0.55,
        .physical => 0.20,
    };
}

fn acValue(ac: AttackComplexity) f64 {
    return switch (ac) {
        .low => 0.77,
        .high => 0.44,
    };
}

fn prValue(pr: PrivilegesRequired, scope: Scope) f64 {
    return switch (pr) {
        .none => 0.85,
        .low => if (scope == .changed) 0.68 else 0.62,
        .high => if (scope == .changed) 0.50 else 0.27,
    };
}

fn uiValue(ui: UserInteraction) f64 {
    return switch (ui) {
        .none => 0.85,
        .required => 0.62,
    };
}

fn cValue(c: ConfidentialityImpact) f64 {
    return switch (c) {
        .high => 0.56,
        .low => 0.22,
        .none => 0,
    };
}

fn iValue(i: IntegrityImpact) f64 {
    return switch (i) {
        .high => 0.56,
        .low => 0.22,
        .none => 0,
    };
}

fn aValue(a: AvailabilityImpact) f64 {
    return switch (a) {
        .high => 0.56,
        .low => 0.22,
        .none => 0,
    };
}

pub fn computeBaseScore(vec: CvssVector) f64 {
    const av = avValue(vec.attack_vector);
    const ac = acValue(vec.attack_complexity);
    const pr = prValue(vec.privileges_required, vec.scope);
    const ui = uiValue(vec.user_interaction);
    const c = cValue(vec.confidentiality);
    const im = iValue(vec.integrity);
    const am = aValue(vec.availability);

    const exploitability = 8.22 * av * ac * pr * ui;
    const iss = 1.0 - (1.0 - c) * (1.0 - im) * (1.0 - am);
    var impact: f64 = undefined;
    if (vec.scope == .unchanged) {
        impact = 6.42 * iss;
    } else {
        impact = 7.52 * (iss - 0.029) - 3.25 * std.math.pow(f64, iss - 0.02, 15.0);
    }
    if (impact <= 0) return 0;
    var score: f64 = undefined;
    if (vec.scope == .unchanged) {
        score = std.math.min(impact + exploitability, 10.0);
    } else {
        score = std.math.min(1.08 * (impact + exploitability), 10.0);
    }
    score = roundTo1Decimal(score);
    return score;
}

pub fn computeTemporalScore(base: f64, vec: CvssVector) f64 {
    const ecm = switch (vec.exploit_code_maturity) {
        .not_defined => 1.0,
        .unproven => 0.91,
        .proof_of_concept => 0.94,
        .functional => 0.97,
        .high => 1.0,
    };
    const rl = switch (vec.remediation_level) {
        .not_defined => 1.0,
        .official_fix => 0.87,
        .temporary_fix => 0.90,
        .workaround => 0.95,
        .unavailable => 1.0,
    };
    const rc = switch (vec.report_confidence) {
        .not_defined => 1.0,
        .unknown => 0.92,
        .reasonable => 0.96,
        .confirmed => 1.0,
    };
    return roundTo1Decimal(base * ecm * rl * rc);
}

pub fn computeEnvironmentalScore(base: f64, vec: CvssVector) f64 {
    _ = base;
    const c_req = 1.0;
    const i_req = 1.0;
    const a_req = 1.0;
    const c = cValue(vec.environmental_confidentiality) * c_req;
    const im = iValue(vec.environmental_integrity) * i_req;
    const am = aValue(vec.environmental_availability) * a_req;
    const iss = 1.0 - (1.0 - c) * (1.0 - im) * (1.0 - am);
    var impact: f64 = undefined;
    if (vec.scope == .unchanged) {
        impact = 6.42 * iss;
    } else {
        impact = 7.52 * (iss - 0.029) - 3.25 * std.math.pow(f64, iss - 0.02, 15.0);
    }
    return roundTo1Decimal(impact);
}

fn roundTo1Decimal(value: f64) f64 {
    return @round(value * 10.0) / 10.0;
}

pub fn scoreEvidence(ev: types.Evidence, allocator: Allocator) !CvssScore {
    var vec = CvssVector{};
    if (ev.severity >= 90) {
        vec.attack_vector = .network;
        vec.confidentiality = .high;
        vec.integrity = .high;
        vec.availability = .high;
        vec.privileges_required = .none;
    } else if (ev.severity >= 70) {
        vec.attack_vector = .network;
        vec.confidentiality = .low;
        vec.integrity = .low;
        vec.availability = .low;
        vec.privileges_required = .low;
    } else if (ev.severity >= 40) {
        vec.attack_vector = .adjacent_network;
        vec.confidentiality = .low;
        vec.integrity = .low;
        vec.availability = .none;
        vec.privileges_required = .low;
    } else {
        vec.attack_vector = .local;
        vec.confidentiality = .none;
        vec.integrity = .low;
        vec.availability = .none;
        vec.privileges_required = .high;
    }

    const base = computeBaseScore(vec);
    const temporal = computeTemporalScore(base, vec);
    const environmental = computeEnvironmentalScore(base, vec);
    const overall = (base + temporal + environmental) / 3.0;

    const vector_str = try std.fmt.allocPrint(allocator, "CVSS:3.1/AV:{s}/AC:{s}/PR:{s}/UI:{s}/S:{s}/C:{s}/I:{s}/A:{s}", .{
        @tagName(vec.attack_vector)[0..1],
        @tagName(vec.attack_complexity)[0..1],
        @tagName(vec.privileges_required)[0..1],
        @tagName(vec.user_interaction)[0..1],
        @tagName(vec.scope)[0..1],
        @tagName(vec.confidentiality)[0..1],
        @tagName(vec.integrity)[0..1],
        @tagName(vec.availability)[0..1],
    });

    return .{
        .base_score = base,
        .temporal_score = temporal,
        .environmental_score = environmental,
        .overall_score = overall,
        .severity = severityFromScore(overall),
        .vector_string = vector_str,
    };
}

pub fn computeAggregateCvss(scores: []const CvssScore) f64 {
    if (scores.len == 0) return 0;
    var total: f64 = 0;
    for (scores) |s| total += s.overall_score;
    return total / @as(f64, @floatFromInt(scores.len));
}

test "cvss - base score for critical finding" {
    const vec = CvssVector{
        .attack_vector = .network,
        .attack_complexity = .low,
        .privileges_required = .none,
        .user_interaction = .none,
        .scope = .unchanged,
        .confidentiality = .high,
        .integrity = .high,
        .availability = .high,
    };
    const score = computeBaseScore(vec);
    try std.testing.expect(score >= 9.0 and score <= 10.0);
}

test "cvss - severity classification" {
    try std.testing.expect(severityFromScore(9.5) == .critical);
    try std.testing.expect(severityFromScore(7.5) == .high);
    try std.testing.expect(severityFromScore(5.0) == .medium);
    try std.testing.expect(severityFromScore(1.0) == .low);
    try std.testing.expect(severityFromScore(0.0) == .none);
}

test "cvss - score evidence mapping" {
    const allocator = std.testing.allocator;
    const ev = types.Evidence{ .function_va = 0, .address = 0x1000, .category = "crypto", .message = "weak cipher", .severity = 85 };
    const score = try scoreEvidence(ev, allocator);
    defer allocator.free(score.vector_string);
    try std.testing.expect(score.severity == .high or score.severity == .critical);
    try std.testing.expect(score.base_score > 0);
}
