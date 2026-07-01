const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const decoder = @import("../core/decoder.zig");

const Allocator = types.Allocator;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const FunctionSpan = types.FunctionSpan;
const InstrKind = types.InstrKind;

pub const PrivacyStandard = enum {
    gdpr,
    ccpa,
    hipaa,
    lgpd,
    pipeda,
    appi,
    none,
};

pub const DataCategory = enum {
    personally_identifiable_information,
    protected_health_information,
    financial_information,
    biometric_data,
    behavioral_data,
    location_data,
    device_identifier,
    authentication_credential,
    payment_card_data,
    childrens_data,
    communication_content,
    unknown,
};

pub const PrivacyPattern = struct {
    name: []const u8,
    category: DataCategory,
    standard: PrivacyStandard,
    severity: u8,
    description: []const u8 = "",
};

pub const PrivacyFinding = struct {
    address: u64,
    function_va: u64,
    pattern: []const u8,
    category: DataCategory,
    standard: PrivacyStandard,
    severity: u8,
    description: []const u8 = "",
    recommendation: []const u8 = "",
    gdpr_articles: []const u8 = "",
    ccpa_sections: []const u8 = "",
};

pub const ConsentCheck = struct {
    address: u64,
    function_va: u64,
    has_consent_check: bool,
    consent_type: []const u8 = "",
    description: []const u8 = "",
};

pub const DataFlowRecord = struct {
    address: u64,
    function_va: u64,
    data_category: DataCategory,
    direction: DataDirection,
    destination: []const u8 = "",
    has_encryption: bool,
    has_consent: bool,
    has_minimization: bool,
};

pub const DataDirection = enum {
    collection,
    storage,
    processing,
    sharing,
    transfer,
    deletion,
};

pub const PrivacyAnalysis = struct {
    findings: []PrivacyFinding,
    data_flows: []DataFlowRecord,
    consent_checks: []ConsentCheck,
    pii_collection_points: usize,
    data_share_operations: usize,
    consent_mechanisms: usize,
    data_retention_policies: usize,
    privacy_gap_score: f64,
    gdpr_compliance_score: f64,
    ccpa_compliance_score: f64,
    hipaa_compliance_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.findings);
        allocator.free(self.data_flows);
        allocator.free(self.consent_checks);
    }
};

const pii_function_patterns = [_]struct { pattern: []const u8, category: DataCategory }{
    .{ .pattern = "email", .category = .personally_identifiable_information },
    .{ .pattern = "ssn", .category = .personally_identifiable_information },
    .{ .pattern = "social_security", .category = .personally_identifiable_information },
    .{ .pattern = "passport", .category = .personally_identifiable_information },
    .{ .pattern = "driver_license", .category = .personally_identifiable_information },
    .{ .pattern = "credit_card", .category = .payment_card_data },
    .{ .pattern = "cvv", .category = .payment_card_data },
    .{ .pattern = "pan", .category = .payment_card_data },
    .{ .pattern = "dob", .category = .personally_identifiable_information },
    .{ .pattern = "date_of_birth", .category = .personally_identifiable_information },
    .{ .pattern = "phone_number", .category = .personally_identifiable_information },
    .{ .pattern = "address", .category = .personally_identifiable_information },
    .{ .pattern = "gps", .category = .location_data },
    .{ .pattern = "geolocation", .category = .location_data },
    .{ .pattern = "latitude", .category = .location_data },
    .{ .pattern = "longitude", .category = .location_data },
    .{ .pattern = "ip_address", .category = .personally_identifiable_information },
    .{ .pattern = "device_id", .category = .device_identifier },
    .{ .pattern = "advertising_id", .category = .device_identifier },
    .{ .pattern = "fingerprint", .category = .biometric_data },
    .{ .pattern = "biometric", .category = .biometric_data },
    .{ .pattern = "password", .category = .authentication_credential },
    .{ .pattern = "token", .category = .authentication_credential },
    .{ .pattern = "session", .category = .authentication_credential },
    .{ .pattern = "diagnosis", .category = .protected_health_information },
    .{ .pattern = "medical_record", .category = .protected_health_information },
    .{ .pattern = "health", .category = .protected_health_information },
    .{ .pattern = "patient", .category = .protected_health_information },
    .{ .pattern = "hipaa", .category = .protected_health_information },
    .{ .pattern = "bank_account", .category = .financial_information },
    .{ .pattern = "routing_number", .category = .financial_information },
    .{ .pattern = "income", .category = .financial_information },
    .{ .pattern = "child", .category = .childrens_data },
    .{ .pattern = "minor", .category = .childrens_data },
    .{ .pattern = "under_", .category = .childrens_data },
};

const data_collection_funcs = [_][]const u8{
    "get", "collect", "gather", "retrieve", "fetch", "obtain", "read", "input",
    "record", "capture", "log", "track", "monitor", "store", "save", "persist",
};

const consent_check_funcs = [_][]const u8{
    "consent", "opt_in", "opt_out", "gdpr_consent", "ccpa_optout",
    "do_not_sell", "privacy_preference", "cookie_consent", "user_consent",
    "permission", "granted", "authorized",
};

pub fn analyzePrivacy(allocator: Allocator, _: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !PrivacyAnalysis {
    var findings = std.ArrayList(PrivacyFinding).init(allocator);
    errdefer findings.deinit();
    var data_flows = std.ArrayList(DataFlowRecord).init(allocator);
    errdefer data_flows.deinit();
    var consent_checks = std.ArrayList(ConsentCheck).init(allocator);
    errdefer consent_checks.deinit();

    var pii_count: usize = 0;
    var share_count: usize = 0;
    var consent_count: usize = 0;

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);

                if (isDataCollectionFunction(resolved.name)) {
                    const cat = classifyDataCategory(resolved.name);
                    try data_flows.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .data_category = cat,
                        .direction = .collection,
                        .destination = "",
                        .has_encryption = false,
                        .has_consent = false,
                        .has_minimization = false,
                    });
                    if (cat == .personally_identifiable_information or cat == .protected_health_information) {
                        pii_count += 1;
                    }
                }

                if (isDataShareFunction(resolved.name)) {
                    const cat = classifyDataCategory(resolved.name);
                    try data_flows.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .data_category = cat,
                        .direction = .sharing,
                        .destination = resolved.name,
                        .has_encryption = false,
                        .has_consent = false,
                        .has_minimization = false,
                    });
                    share_count += 1;
                }

                if (isConsentCheckFunction(resolved.name)) {
                    try consent_checks.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .has_consent_check = true,
                        .consent_type = resolved.name,
                    });
                    consent_count += 1;
                }

                if (containsPIIPattern(resolved.name)) |cat| {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .pattern = resolved.name,
                        .category = cat,
                        .standard = .gdpr,
                        .severity = 60,
                        .description = try std.fmt.allocPrint(allocator, "PII data handled via: {s}", .{resolved.name}),
                        .recommendation = "Ensure proper consent, minimization, and encryption for PII",
                        .gdpr_articles = "Art. 5, 6, 9, 32",
                        .ccpa_sections = "Sec. 1798.100, 1798.105",
                    });
                }
            }
        }
    }

    var gdpr_findings: usize = 0;
    var ccpa_findings: usize = 0;
    var hipaa_findings: usize = 0;

    for (data_flows.items) |flow| {
        if (flow.data_category == .payment_card_data or flow.data_category == .financial_information) {
            gdpr_findings += 1;
        }
        if (flow.data_category == .personally_identifiable_information and flow.direction == .sharing) {
            ccpa_findings += 1;
        }
        if (flow.data_category == .protected_health_information) {
            hipaa_findings += 1;
        }
    }

    if (pii_count > 0 and consent_count == 0) {
        try findings.append(.{
            .address = 0,
            .function_va = 0,
            .pattern = "missing_consent",
            .category = .personally_identifiable_information,
            .standard = .gdpr,
            .severity = 85,
            .description = "PII collection without consent mechanism detected",
            .recommendation = "Implement GDPR-compliant consent collection",
            .gdpr_articles = "Art. 7, 8",
            .ccpa_sections = "Sec. 1798.120",
        });
    }

    if (share_count > 0 and consent_count == 0) {
        try findings.append(.{
            .address = 0,
            .function_va = 0,
            .pattern = "data_sharing_no_consent",
            .category = .personally_identifiable_information,
            .standard = .ccpa,
            .severity = 80,
            .description = "Data sharing without opt-out mechanism",
            .recommendation = "Implement CCPA 'Do Not Sell' opt-out",
            .ccpa_sections = "Sec. 1798.120",
        });
    }

    const privacy_score = computePrivacyScore(findings.items, data_flows.items, consent_checks.items);
    const gdpr_score = computeStandardScore(findings.items, data_flows.items, .gdpr);
    const ccpa_score = computeStandardScore(findings.items, data_flows.items, .ccpa);
    const hipaa_score = computeStandardScore(findings.items, data_flows.items, .hipaa);

    return .{
        .findings = try findings.toOwnedSlice(),
        .data_flows = try data_flows.toOwnedSlice(),
        .consent_checks = try consent_checks.toOwnedSlice(),
        .pii_collection_points = pii_count,
        .data_share_operations = share_count,
        .consent_mechanisms = consent_count,
        .data_retention_policies = 0,
        .privacy_gap_score = privacy_score,
        .gdpr_compliance_score = gdpr_score,
        .ccpa_compliance_score = ccpa_score,
        .hipaa_compliance_score = hipaa_score,
    };
}

fn isDataCollectionFunction(name: []const u8) bool {
    return utils.containsAny(name, &data_collection_funcs);
}

fn isDataShareFunction(name: []const u8) bool {
    return utils.containsAny(name, &.{ "send", "upload", "share", "transmit", "forward", "export", "submit", "publish", "post", "sync" });
}

fn isConsentCheckFunction(name: []const u8) bool {
    return utils.containsAny(name, &consent_check_funcs);
}

fn containsPIIPattern(name: []const u8) ?DataCategory {
    const lower = name;
    for (pii_function_patterns) |entry| {
        if (utils.asciiContainsIgnoreCase(lower, entry.pattern)) return entry.category;
    }
    return null;
}

fn classifyDataCategory(name: []const u8) DataCategory {
    if (containsPIIPattern(name)) |cat| return cat;
    if (utils.containsAny(name, &.{ "email", "phone", "name", "username" })) return .personally_identifiable_information;
    if (utils.containsAny(name, &.{ "payment", "credit", "debit", "card_number" })) return .payment_card_data;
    if (utils.containsAny(name, &.{ "location", "coordinate", "geo" })) return .location_data;
    if (utils.containsAny(name, &.{ "advertising", "ad_id" })) return .device_identifier;
    return .unknown;
}

fn computePrivacyScore(findings: []const PrivacyFinding, flows: []const DataFlowRecord, consents: []const ConsentCheck) f64 {
    var score: f64 = 0;
    for (findings) |f| {
        score += @as(f64, @floatFromInt(f.severity)) * 0.25;
    }
    var unencrypted: usize = 0;
    for (flows) |f| {
        if (f.direction == .sharing and !f.has_encryption) unencrypted += 1;
    }
    if (flows.len > 0) {
        score += @as(f64, @floatFromInt(unencrypted)) * 20.0 / @as(f64, @floatFromInt(flows.len));
    }
    if (findings.len > 0 and consents.len == 0) score += 30;
    return utils.clamp100(score);
}

fn computeStandardScore(findings: []const PrivacyFinding, flows: []const DataFlowRecord, standard: PrivacyStandard) f64 {
    var relevant: usize = 0;
    var issues: usize = 0;
    for (findings) |f| {
        if (f.standard == standard) {
            relevant += 1;
            if (f.severity >= 60) issues += 1;
        }
    }
    for (flows) |f| {
        switch (standard) {
            .gdpr => {
                if (f.data_category == .personally_identifiable_information or
                    f.data_category == .protected_health_information) relevant += 1;
            },
            .ccpa => {
                if (f.data_category == .personally_identifiable_information) relevant += 1;
            },
            .hipaa => {
                if (f.data_category == .protected_health_information) relevant += 1;
            },
            else => {},
        }
    }
    if (relevant == 0) return 100;
    return utils.clamp100(100.0 - @as(f64, @floatFromInt(issues)) * 100.0 / @as(f64, @floatFromInt(relevant)));
}

pub fn detectDataRetention(allocator: Allocator, bytes: []const u8) ![]PrivacyFinding {
    var findings = std.ArrayList(PrivacyFinding).init(allocator);
    errdefer findings.deinit();

    const retention_patterns = [_][]const u8{
        "retention_period", "retention_days", "data_retention",
        "delete_after", "expire_after", "ttl_seconds",
        "max_age", "keep_alive", "session_timeout",
    };

    var found_retention = false;
    for (retention_patterns) |pattern| {
        if (std.mem.indexOf(u8, bytes, pattern) != null) {
            found_retention = true;
            break;
        }
    }

    if (!found_retention) {
        try findings.append(.{
            .address = 0,
            .function_va = 0,
            .pattern = "no_retention_policy",
            .category = .personally_identifiable_information,
            .standard = .gdpr,
            .severity = 65,
            .description = "No data retention policy detected",
            .recommendation = "Implement data retention and deletion policies as required by Art. 5(1)(e) GDPR",
            .gdpr_articles = "Art. 5, 17, 18",
        });
    }

    return findings.toOwnedSlice();
}

pub fn checkThirdPartySharing(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]PrivacyFinding {
    var findings = std.ArrayList(PrivacyFinding).init(allocator);
    errdefer findings.deinit();

    const third_party_sdks = [_][]const u8{
        "google_analytics", "firebase", "facebook", "twitter", "adjust",
        "appsflyer", "amplitude", "mixpanel", "segment", "braze",
        "optimizely", "leanplum", "localytics", "flurry",
    };

    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            for (third_party_sdks) |sdk| {
                if (utils.asciiContainsIgnoreCase(resolved.name, sdk)) {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = 0,
                        .pattern = resolved.name,
                        .category = .behavioral_data,
                        .standard = .ccpa,
                        .severity = 70,
                        .description = try std.fmt.allocPrint(allocator, "Third-party SDK data sharing: {s}", .{resolved.name}),
                        .recommendation = "Disclose third-party data sharing and provide opt-out per CCPA",
                        .ccpa_sections = "Sec. 1798.115, 1798.120",
                    });
                    break;
                }
            }
        }
    }

    return findings.toOwnedSlice();
}
