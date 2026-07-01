const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub const StrideCategory = enum {
    spoofing,
    tampering,
    repudiation,
    information_disclosure,
    denial_of_service,
    elevation_of_privilege,
};

pub const PastaPhase = enum {
    define_objectives,
    define_technical_scope,
    decompose_application,
    threat_analysis,
    weakness_identification,
    attack_modeling,
    risk_analysis,
};

pub const ThreatIntent = enum {
    opportunistic,
    targeted,
    insider,
    apt,
    hacktivism,
    unknown,
};

pub const AttackVector = enum {
    network,
    adjacent_network,
    local,
    physical,
    remote_physical,
};

pub const ThreatEntry = struct {
    stride: StrideCategory,
    name: []const u8,
    description: []const u8,
    cwe_ids: []const u32,
    likelihood: u8,
    impact: u8,
    attack_vector: AttackVector = .network,
    requires_authentication: bool = true,
    pasta_phase: PastaPhase = .threat_analysis,
};

pub const AttackTree = struct {
    root_threat: []const u8,
    children: []AttackTreeNode,
    mitigations: []const u8,
    risk_score: f64,
};

pub const AttackTreeNode = struct {
    node_type: AttackNodeType,
    description: []const u8,
    children: []AttackTreeNode = &[_]AttackTreeNode{},
    condition: []const u8 = "",
};

pub const AttackNodeType = enum {
    and_gate,
    or_gate,
    leaf_action,
    condition,
    countermeasure,
};

pub const ThreatModelResult = struct {
    threats: []ThreatEntry,
    attack_trees: []AttackTree,
    stride_coverage: [7]StrideCoverage,
    overall_risk: f64,
    high_risk_threats: usize,
    total_threats: usize,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.threats);
        allocator.free(self.attack_trees);
    }
};

pub const StrideCoverage = struct {
    category: StrideCategory,
    threat_count: usize,
    avg_likelihood: f64,
    avg_impact: f64,
    risk_score: f64,
};

pub fn classifyStride(findings: []const types.Evidence, allocator: Allocator) !ThreatModelResult {
    var threats = std.ArrayList(ThreatEntry).init(allocator);
    errdefer threats.deinit();
    var coverage = [_]StrideCoverage{
        .{ .category = .spoofing, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
        .{ .category = .tampering, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
        .{ .category = .repudiation, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
        .{ .category = .information_disclosure, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
        .{ .category = .denial_of_service, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
        .{ .category = .elevation_of_privilege, .threat_count = 0, .avg_likelihood = 0, .avg_impact = 0, .risk_score = 0 },
    };

    for (findings) |ev| {
        const stride = mapEvidenceToStride(ev.category);
        const idx = @intFromEnum(stride);
        coverage[idx].threat_count += 1;
        const likelihood = @as(f64, @floatFromInt(ev.severity)) / 100.0;
        coverage[idx].avg_likelihood += likelihood;
        coverage[idx].avg_impact += likelihood;

        try threats.append(.{
            .stride = stride,
            .name = ev.category,
            .description = ev.message,
            .cwe_ids = if (ev.cwe_id > 0) &[_]u32{ev.cwe_id} else &[_]u32{},
            .likelihood = ev.severity,
            .impact = ev.severity,
            .attack_vector = classifyAttackVector(ev.category),
            .requires_authentication = true,
            .pasta_phase = .threat_analysis,
        });
    }

    var total_risk: f64 = 0;
    var high_count: usize = 0;
    for (&coverage, 0..) |*cov, i| {
        if (cov.threat_count > 0) {
            cov.avg_likelihood /= @as(f64, @floatFromInt(cov.threat_count));
            cov.avg_impact /= @as(f64, @floatFromInt(cov.threat_count));
            cov.risk_score = cov.avg_likelihood * cov.avg_impact * 100.0;
            total_risk += cov.risk_score;
            if (cov.risk_score > 50) high_count += 1;
        }
    }

    return .{
        .threats = try threats.toOwnedSlice(),
        .attack_trees = try allocator.alloc(AttackTree, 0),
        .stride_coverage = coverage,
        .overall_risk = total_risk / 6.0,
        .high_risk_threats = high_count,
        .total_threats = threats.items.len,
    };
}

fn mapEvidenceToStride(category: []const u8) StrideCategory {
    if (std.mem.eql(u8, category, "authentication") or std.mem.eql(u8, category, "credential")) return .spoofing;
    if (std.mem.eql(u8, category, "integrity") or std.mem.eql(u8, category, "tampering")) return .tampering;
    if (std.mem.eql(u8, category, "logging") or std.mem.eql(u8, category, "audit")) return .repudiation;
    if (std.mem.eql(u8, category, "privacy") or std.mem.eql(u8, category, "crypto") or std.mem.eql(u8, category, "information_disclosure")) return .information_disclosure;
    if (std.mem.eql(u8, category, "availability") or std.mem.eql(u8, category, "resource")) return .denial_of_service;
    if (std.mem.eql(u8, category, "authorization") or std.mem.eql(u8, category, "privilege")) return .elevation_of_privilege;
    return .tampering;
}

fn classifyAttackVector(category: []const u8) AttackVector {
    if (std.mem.indexOf(u8, category, "network") != null or std.mem.indexOf(u8, category, "remote") != null) return .network;
    if (std.mem.indexOf(u8, category, "local") != null) return .local;
    return .network;
}

pub fn buildAttackTree(allocator: Allocator, threat: ThreatEntry) !AttackTree {
    _ = allocator;
    return .{
        .root_threat = threat.name,
        .children = &[_]AttackTreeNode{},
        .mitigations = "Implement security controls per STRIDE category",
        .risk_score = @as(f64, @floatFromInt(threat.likelihood)) * @as(f64, @floatFromInt(threat.impact)) / 100.0,
    };
}

pub fn performPastaAnalysis(allocator: Allocator, image: types.BinaryImage, findings: []const types.Evidence) !ThreatModelResult {
    _ = image;
    const result = try classifyStride(findings, allocator);
    return result;
}

test "threat model - stride classification" {
    const allocator = std.testing.allocator;
    var evidence = try allocator.alloc(types.Evidence, 3);
    defer allocator.free(evidence);
    evidence[0] = .{ .function_va = 0, .address = 0, .category = "crypto", .message = "weak cipher", .severity = 80 };
    evidence[1] = .{ .function_va = 0, .address = 0, .category = "logging", .message = "no audit", .severity = 60 };
    evidence[2] = .{ .function_va = 0, .address = 0, .category = "authentication", .message = "no auth", .severity = 90 };
    const result = try classifyStride(evidence, allocator);
    defer result.deinit(allocator);
    try std.testing.expect(result.total_threats == 3);
    try std.testing.expect(result.stride_coverage[@intFromEnum(StrideCategory.information_disclosure)].threat_count >= 1);
}

test "threat model - attack vector classification" {
    const vec = classifyAttackVector("network_input");
    try std.testing.expect(vec == .network);
    const vec2 = classifyAttackVector("local_file");
    try std.testing.expect(vec2 == .local);
}
