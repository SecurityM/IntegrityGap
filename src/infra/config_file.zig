const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub const AnalysisConfig = struct {
    max_bytes: usize = types.default_max_bytes,
    verbose: bool = false,
    json_output: ?[]const u8 = null,
    dot_output: ?[]const u8 = null,
    html_output: ?[]const u8 = null,
    markdown_output: ?[]const u8 = null,
    sarif_output: ?[]const u8 = null,
    compliance_framework: ?[]const u8 = null,
    mode: ConfigMode = .all,
    baseline_path: ?[]const u8 = null,
    diff_path: ?[]const u8 = null,
    batch_file: ?[]const u8 = null,
    report_only: bool = false,
    firmware_check: bool = false,
    baseline_dir: ?[]const u8 = null,
    plugins: []const PluginConfig = &[_]PluginConfig{},
    log_level: []const u8 = "info",
    log_file: ?[]const u8 = null,
    cache_enabled: bool = false,
    cache_directory: ?[]const u8 = null,
    excluded_categories: []const []const u8 = &[_][]const u8{},
    min_severity: u8 = 0,
    max_findings: usize = 0,
    enable_fp_reduction: bool = true,
    enable_remediation: bool = true,
    enable_cvss: bool = true,
};

pub const PluginConfig = struct {
    name: []const u8,
    path: []const u8,
    enabled: bool = true,
    config: ?[]const u8 = null,
};

pub const ConfigMode = enum {
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
};

pub fn parseConfigFile(allocator: Allocator, path: []const u8) !AnalysisConfig {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var config = AnalysisConfig{};
    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();
    var line_buf: [4096]u8 = undefined;

    while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |raw_line| {
        const line = std.mem.trim(u8, raw_line, &std.ascii.whitespace);
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        if (!std.mem.startsWith(u8, line, "--")) {
            if (config.json_output == null and config.html_output == null and config.sarif_output == null) {
                config.json_output = try allocator.dupe(u8, line);
            }
            continue;
        }

        var it = std.mem.splitScalar(u8, line, '=');
        const key = std.mem.trim(u8, it.first(), &std.ascii.whitespace);
        const value = if (it.next()) |v| std.mem.trim(u8, v, &std.ascii.whitespace) else "true";

        applyConfigField(&config, allocator, key, value) catch continue;
    }

    return config;
}

fn applyConfigField(config: *AnalysisConfig, allocator: Allocator, key: []const u8, value: []const u8) !void {
    if (std.mem.eql(u8, key, "--max-bytes")) {
        config.max_bytes = try std.fmt.parseInt(usize, value, 10);
    } else if (std.mem.eql(u8, key, "--verbose") or std.mem.eql(u8, key, "-v")) {
        config.verbose = parseBool(value);
    } else if (std.mem.eql(u8, key, "--json")) {
        config.json_output = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--dot")) {
        config.dot_output = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--html")) {
        config.html_output = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--markdown") or std.mem.eql(u8, key, "--md")) {
        config.markdown_output = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--sarif")) {
        config.sarif_output = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--mode")) {
        config.mode = parseConfigMode(value);
    } else if (std.mem.eql(u8, key, "--compliance")) {
        config.compliance_framework = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--baseline")) {
        config.baseline_path = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--diff")) {
        config.diff_path = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--batch")) {
        config.batch_file = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--log-level")) {
        config.log_level = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--log-file")) {
        config.log_file = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--firmware")) {
        config.firmware_check = parseBool(value);
    } else if (std.mem.eql(u8, key, "--report-only")) {
        config.report_only = parseBool(value);
    } else if (std.mem.eql(u8, key, "--cache-enabled")) {
        config.cache_enabled = parseBool(value);
    } else if (std.mem.eql(u8, key, "--cache-directory")) {
        config.cache_directory = try allocator.dupe(u8, value);
    } else if (std.mem.eql(u8, key, "--min-severity")) {
        config.min_severity = try std.fmt.parseInt(u8, value, 10);
    } else if (std.mem.eql(u8, key, "--max-findings")) {
        config.max_findings = try std.fmt.parseInt(usize, value, 10);
    } else if (std.mem.eql(u8, key, "--fp-reduction")) {
        config.enable_fp_reduction = parseBool(value);
    } else if (std.mem.eql(u8, key, "--enable-remediation")) {
        config.enable_remediation = parseBool(value);
    } else if (std.mem.eql(u8, key, "--enable-cvss")) {
        config.enable_cvss = parseBool(value);
    }
}

fn parseBool(value: []const u8) bool {
    return std.mem.eql(u8, value, "true") or
        std.mem.eql(u8, value, "yes") or
        std.mem.eql(u8, value, "1") or
        std.mem.eql(u8, value, "on");
}

fn parseConfigMode(value: []const u8) ConfigMode {
    const modes = [_]struct { name: []const u8, mode: ConfigMode }{
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
    };
    for (modes) |entry| {
        if (std.mem.eql(u8, value, entry.name)) return entry.mode;
    }
    return .all;
}

pub fn mergeWithArgs(config: AnalysisConfig, allocator: Allocator) !AnalysisConfig {
    _ = allocator;
    return config;
}

test "config file - parsing" {
    const allocator = std.testing.allocator;
    const test_cfg = try std.fs.cwd().createFile("/tmp/test_integritygap.conf", .{ .read = true });
    defer test_cfg.close();
    try test_cfg.writeAll(
        \\# IntegrityGap config
        \\--verbose=true
        \\--json=report.json
        \\--mode=all
        \\--max-bytes=134217728
        \\; another comment
        \\target.exe
    );
    const cfg = try parseConfigFile(allocator, "/tmp/test_integritygap.conf");
    defer {
        allocator.free(cfg.json_output.?);
    }
    try std.testing.expect(cfg.verbose == true);
    try std.testing.expect(cfg.max_bytes == 134217728);
    try std.testing.expect(cfg.mode == .all);
    try std.testing.expect(cfg.json_output != null);
    try std.testing.expect(std.mem.eql(u8, cfg.json_output.?, "report.json"));
}

test "config file - empty config" {
    const allocator = std.testing.allocator;
    const test_cfg = try std.fs.cwd().createFile("/tmp/test_empty.conf", .{ .read = true });
    defer test_cfg.close();
    const cfg = try parseConfigFile(allocator, "/tmp/test_empty.conf");
    try std.testing.expect(cfg.verbose == false);
    try std.testing.expect(cfg.max_bytes == types.default_max_bytes);
}
