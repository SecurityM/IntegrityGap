const std = @import("std");
const types = @import("../types.zig");
const utils = @import("../core/utils.zig");
const decoder = @import("../core/decoder.zig");

const Allocator = types.Allocator;
const Decoded = types.Decoded;
const BinaryImage = types.BinaryImage;
const FunctionSpan = types.FunctionSpan;
const InstrKind = types.InstrKind;

pub const ConfigIssueType = enum {
    hardcoded_credential,
    insecure_default,
    missing_authentication,
    permissive_permission,
    debug_mode_enabled,
    verbose_error_handling,
    disabled_security_feature,
    weak_configuration,
    exposed_internal_path,
    missing_encryption_config,
    default_password,
    unencrypted_storage,
    disabled_audit_logging,
    overly_broad_cors,
    insecure_protocol_enabled,
    missing_input_validation_config,
};

pub const ConfigSetting = struct {
    name: []const u8,
    value: []const u8,
    is_default: bool,
    is_secure: bool,
    source: ConfigSource,
    severity: u8,
    address: u64 = 0,
};

pub const ConfigSource = enum {
    binary_data_section,
    code_constant,
    registry_setting,
    configuration_file,
    environment_variable,
    command_line_arg,
    embedded_resource,
    hardcoded_string,
};

pub const ConfigFinding = struct {
    address: u64,
    function_va: u64,
    issue_type: ConfigIssueType,
    severity: u8,
    setting_name: []const u8 = "",
    current_value: []const u8 = "",
    recommended_value: []const u8 = "",
    description: []const u8 = "",
    recommendation: []const u8 = "",
};

pub const SecurityControl = struct {
    name: []const u8,
    present: bool,
    enabled: bool,
    configured_correctly: bool,
    severity: u8,
};

pub const ConfigAudit = struct {
    settings: []ConfigSetting,
    findings: []ConfigFinding,
    controls: []SecurityControl,
    hardcoded_credentials: usize,
    insecure_defaults: usize,
    disabled_security: usize,
    total_settings_checked: usize,
    config_security_score: f64,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.settings);
        allocator.free(self.findings);
        allocator.free(self.controls);
    }
};

const credential_patterns = [_][]const u8{
    "password", "passwd", "pwd", "secret", "apikey", "api_key",
    "access_key", "secret_key", "private_key", "token", "auth_token",
    "connection_string", "conn_string", "db_password", "db_user",
};

const insecure_default_patterns = [_][]const u8{
    "admin", "root", "default", "guest", "test", "debug",
    "disabled", "false", "none", "allow_all", "permit_all",
    "0.0.0.0", "localhost", "127.0.0.1",
};

const security_control_names = [_][]const u8{
    "authentication_enabled", "encryption_enabled", "audit_logging",
    "rate_limiting", "session_timeout", "account_lockout",
    "password_complexity", "mfa_required", "tls_version",
    "csp_enabled", "xss_protection", "csrf_protection",
};

pub fn auditConfiguration(allocator: Allocator, bytes: []const u8, instrs: []const Decoded, image: BinaryImage, functions: []const FunctionSpan) !ConfigAudit {
    var settings = std.ArrayList(ConfigSetting).init(allocator);
    errdefer settings.deinit();
    var findings = std.ArrayList(ConfigFinding).init(allocator);
    errdefer findings.deinit();
    var controls = std.ArrayList(SecurityControl).init(allocator);
    errdefer controls.deinit();

    var hc_count: usize = 0;
    var insecure_count: usize = 0;
    var disabled_count: usize = 0;

    for (image.sections) |section| {
        if (!section.executable) {
            const data = bytes[section.file_offset..@min(section.file_offset + section.size, bytes.len)];

            for (credential_patterns) |pattern| {
                var search_off: usize = 0;
                while (std.mem.indexOf(u8, data[search_off..], pattern)) |match| {
                    const abs_off = section.file_offset + search_off + match;
                    const value_start = abs_off + pattern.len;
                    var value: []const u8 = "";
                    if (value_start < bytes.len) {
                        const remaining = bytes[value_start..@min(value_start + 64, bytes.len)];
                        const end = std.mem.indexOfScalar(u8, remaining, 0) orelse remaining.len;
                        value = remaining[0..@min(end, @as(usize, 32))];
                    }

                    try settings.append(.{
                        .name = pattern,
                        .value = value,
                        .is_default = false,
                        .is_secure = false,
                        .source = .binary_data_section,
                        .severity = 85,
                        .address = abs_off,
                    });

                    try findings.append(.{
                        .address = abs_off,
                        .function_va = 0,
                        .issue_type = .hardcoded_credential,
                        .severity = 85,
                        .setting_name = pattern,
                        .current_value = value,
                        .recommended_value = "Use secure credential store / environment variables",
                        .description = "Hardcoded credential pattern detected in binary",
                        .recommendation = "Remove hardcoded secrets; use vault or environment variables",
                    });
                    hc_count += 1;
                    search_off = abs_off - section.file_offset + 1;
                }
            }

            for (insecure_default_patterns) |pattern| {
                if (std.mem.indexOf(u8, data, pattern)) |_| {
                    insecure_count += 1;
                    try settings.append(.{
                        .name = pattern,
                        .value = pattern,
                        .is_default = true,
                        .is_secure = false,
                        .source = .binary_data_section,
                        .severity = 50,
                    });
                }
            }
        }
    }

    for (functions) |function| {
        const func_instrs = instrs[function.instr_start..function.instr_end];
        for (func_instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                const name = resolved.name;

                if (utils.containsAny(name, &.{ "RegSetValueEx", "WritePrivateProfileString", "WriteProfileString" })) {
                    try settings.append(.{
                        .name = "registry_config_write",
                        .value = name,
                        .is_default = false,
                        .is_secure = false,
                        .source = .registry_setting,
                        .severity = 40,
                        .address = instr.va,
                    });
                }

                if (utils.containsAny(name, &.{ "getenv", "GetEnvironmentVariable", "GetEnv" })) {
                    try settings.append(.{
                        .name = "env_config_read",
                        .value = name,
                        .is_default = false,
                        .is_secure = true,
                        .source = .environment_variable,
                        .severity = 10,
                        .address = instr.va,
                    });
                }

                if (utils.containsAny(name, &.{ "SetSecurityDescriptorDacl", "SetSecurityInfo", "SetFileSecurity" })) {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .issue_type = .permissive_permission,
                        .severity = 75,
                        .setting_name = name,
                        .description = "Security descriptor manipulation - verify permissions are least-privilege",
                        .recommendation = "Apply principle of least privilege to all security descriptors",
                    });
                }

                if (utils.containsAny(name, &.{ "DebugActiveProcess", "IsDebuggerPresent", "CheckRemoteDebuggerPresent" })) {
                    try findings.append(.{
                        .address = instr.va,
                        .function_va = function.start,
                        .issue_type = .debug_mode_enabled,
                        .severity = 60,
                        .setting_name = "debug_mode",
                        .description = "Debug/diagnostic mode detected in binary",
                        .recommendation = "Disable debug mode in production builds",
                    });
                }

                if (utils.containsAny(name, &.{ "Disable", "disable", "turn_off", "skip_verify" })) {
                    if (utils.containsAny(name, &.{ "ssl", "tls", "crypto", "auth", "secure" })) {
                        try findings.append(.{
                            .address = instr.va,
                            .function_va = function.start,
                            .issue_type = .disabled_security_feature,
                            .severity = 90,
                            .setting_name = name,
                            .description = "Security feature explicitly disabled",
                            .recommendation = "Enable and properly configure security features",
                        });
                        disabled_count += 1;
                    }
                }
            }

            if (instr.kind == .mov and instr.op_count >= 2) {
                const dst = instr.operand(0);
                const src = instr.operand(1);
                if (dst.kind == .mem and src.kind == .imm) {
                    if (src.imm == 1 or src.imm == 0) {
                    }
                }
            }
        }
    }

    for (security_control_names) |ctrl_name| {
        var found = false;
        for (instrs) |instr| {
            if (instr.kind == .call) {
                const resolved = decoder.resolveCallInfo(image, instr);
                if (utils.asciiContainsIgnoreCase(resolved.name, ctrl_name)) {
                    found = true;
                    break;
                }
            }
        }
        try controls.append(.{
            .name = ctrl_name,
            .present = found,
            .enabled = false,
            .configured_correctly = false,
            .severity = if (found) @as(u8, 20) else @as(u8, 70),
        });
    }

    const score = computeConfigScore(findings.items, controls.items);

    return .{
        .settings = try settings.toOwnedSlice(),
        .findings = try findings.toOwnedSlice(),
        .controls = try controls.toOwnedSlice(),
        .hardcoded_credentials = hc_count,
        .insecure_defaults = insecure_count,
        .disabled_security = disabled_count,
        .total_settings_checked = settings.items.len,
        .config_security_score = score,
    };
}

fn computeConfigScore(findings: []const ConfigFinding, controls: []const SecurityControl) f64 {
    var score: f64 = 100;
    for (findings) |f| {
        score -= @as(f64, @floatFromInt(f.severity)) * 0.5;
    }
    var missing_controls: usize = 0;
    for (controls) |ctrl| {
        if (!ctrl.present) missing_controls += 1;
    }
    if (controls.len > 0) {
        score -= @as(f64, @floatFromInt(missing_controls)) * 15.0 / @as(f64, @floatFromInt(controls.len));
    }
    return utils.clamp100(score);
}

pub fn detectCorsMisconfiguration(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]ConfigFinding {
    var findings = std.ArrayList(ConfigFinding).init(allocator);
    errdefer findings.deinit();

    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (utils.containsAny(resolved.name, &.{ "Access-Control-Allow-Origin", "setHeader", "addHeader" })) {
                try findings.append(.{
                    .address = instr.va,
                    .function_va = 0,
                    .issue_type = .overly_broad_cors,
                    .severity = 65,
                    .setting_name = "CORS",
                    .description = "CORS header manipulation - verify wildcard not used",
                    .recommendation = "Restrict Access-Control-Allow-Origin to specific origins",
                });
            }
        }
    }

    return findings.toOwnedSlice();
}

pub fn analyzeLoggingConfig(allocator: Allocator, instrs: []const Decoded, image: BinaryImage) ![]ConfigFinding {
    var findings = std.ArrayList(ConfigFinding).init(allocator);
    errdefer findings.deinit();

    var has_audit_logging = false;
    var has_verbose_errors = false;

    for (instrs) |instr| {
        if (instr.kind == .call) {
            const resolved = decoder.resolveCallInfo(image, instr);
            if (utils.containsAny(resolved.name, &.{ "audit", "Audit", "syslog", "EventLog", "eventlog" })) {
                has_audit_logging = true;
            }
            if (utils.containsAny(resolved.name, &.{ "verbose", "Verbose", "debug_log", "stack_trace" })) {
                has_verbose_errors = true;
            }
        }
    }

    if (!has_audit_logging) {
        try findings.append(.{
            .address = 0,
            .function_va = 0,
            .issue_type = .disabled_audit_logging,
            .severity = 55,
            .setting_name = "audit_logging",
            .description = "No audit logging mechanism detected",
            .recommendation = "Enable audit logging for security events",
        });
    }

    if (has_verbose_errors) {
        try findings.append(.{
            .address = 0,
            .function_va = 0,
            .issue_type = .verbose_error_handling,
            .severity = 45,
            .setting_name = "error_reporting",
            .description = "Verbose error handling may leak sensitive information",
            .recommendation = "Use generic error messages in production",
        });
    }

    return findings.toOwnedSlice();
}
