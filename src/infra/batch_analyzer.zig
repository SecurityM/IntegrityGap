const std = @import("std");
const types = @import("../types.zig");
const analyzer = @import("../core/analyzer.zig");
const logging = @import("logging.zig");

const Allocator = types.Allocator;

pub const ProgressCallback = *const fn (current: usize, total: usize, current_file: []const u8, allocator: Allocator) void;

pub const BatchItem = struct {
    path: []const u8,
    max_bytes: usize = types.default_max_bytes,
    mode: BatchMode = .full,
};

pub const BatchMode = enum {
    full,
    quick,
    integrity_only,
    compliance_only,
};

pub const BatchResult = struct {
    item_path: []const u8,
    success: bool,
    error_message: []const u8 = "",
    function_count: usize = 0,
    gap_score: f64 = 0,
    analysis_time_ms: u64 = 0,
};

pub const BatchSummary = struct {
    total_items: usize,
    successful: usize,
    failed: usize,
    total_functions: usize,
    average_gap_score: f64,
    total_time_ms: u64,
    results: []BatchResult,

    pub fn deinit(self: *@This(), allocator: Allocator) void {
        allocator.free(self.results);
    }
};

pub fn processBatch(allocator: Allocator, items: []const BatchItem, verbose: bool, progress_cb: ?ProgressCallback) !BatchSummary {
    var results = std.ArrayList(BatchResult).init(allocator);
    errdefer results.deinit();

    var success_count: usize = 0;
    var fail_count: usize = 0;
    var total_funcs: usize = 0;
    var total_gap: f64 = 0;
    const start_time = std.time.milliTimestamp();

    for (items, 0..) |item, idx| {
        if (progress_cb) |cb| cb(idx + 1, items.len, item.path, allocator);

        const item_start = std.time.milliTimestamp();
        const result = analyzeItem(allocator, item, verbose) catch |err| {
            fail_count += 1;
            try results.append(.{
                .item_path = item.path,
                .success = false,
                .error_message = switch (err) {
                    error.FileNotFound => "File not found",
                    error.AccessDenied => "Access denied",
                    error.UnsupportedBinaryFormat => "Unsupported binary format",
                    else => "Analysis failed",
                },
                .analysis_time_ms = @intCast(std.time.milliTimestamp() - item_start),
            });
            continue;
        };

        success_count += 1;
        total_funcs += result.function_count;
        total_gap += result.gap_score;
        try results.append(result);
    }

    const total_time = @as(u64, @intCast(std.time.milliTimestamp() - start_time));

    return .{
        .total_items = items.len,
        .successful = success_count,
        .failed = fail_count,
        .total_functions = total_funcs,
        .average_gap_score = if (success_count > 0) total_gap / @as(f64, @floatFromInt(success_count)) else 0,
        .total_time_ms = total_time,
        .results = try results.toOwnedSlice(),
    };
}

fn analyzeItem(allocator: Allocator, item: BatchItem, verbose: bool) !BatchResult {
    const start = std.time.milliTimestamp();
    const analysis = try analyzer.analyzeTarget(allocator, item.path, item.max_bytes, verbose);
    defer analysis.deinit(allocator);

    return .{
        .item_path = item.path,
        .success = true,
        .function_count = analysis.functions.len,
        .gap_score = analysis.summary.aggregate_gap,
        .analysis_time_ms = @intCast(std.time.milliTimestamp() - start),
    };
}

pub fn loadBatchFile(allocator: Allocator, file_path: []const u8) ![]BatchItem {
    var items = std.ArrayList(BatchItem).init(allocator);
    errdefer items.deinit();

    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    const reader = buf_reader.reader();
    var line_buf: [8192]u8 = undefined;

    while (try reader.readUntilDelimiterOrEof(&line_buf, '\n')) |line| {
        const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var mode: BatchMode = .full;
        var max_bytes: usize = types.default_max_bytes;

        if (std.mem.indexOf(u8, trimmed, "|")) |pipe_pos| {
            const path_part = std.mem.trim(u8, trimmed[0..pipe_pos], &std.ascii.whitespace);
            const options = std.mem.trim(u8, trimmed[pipe_pos + 1 ..], &std.ascii.whitespace);
            if (std.mem.eql(u8, options, "quick")) mode = .quick;
            if (std.mem.eql(u8, options, "integrity")) mode = .integrity_only;
            try items.append(.{ .path = try allocator.dupe(u8, path_part), .max_bytes = max_bytes, .mode = mode });
        } else {
            try items.append(.{ .path = try allocator.dupe(u8, trimmed), .max_bytes = max_bytes, .mode = mode });
        }
    }

    return items.toOwnedSlice();
}

pub fn printBatchSummary(summary: BatchSummary) !void {
    const out = std.io.getStdOut().writer();
    try out.print("\n=== Batch Analysis Summary ===\n", .{});
    try out.print("Total items: {}\n", .{summary.total_items});
    try out.print("Successful: {}\n", .{summary.successful});
    try out.print("Failed: {}\n", .{summary.failed});
    try out.print("Total functions analyzed: {}\n", .{summary.total_functions});
    try out.print("Average gap score: {d:.2}\n", .{summary.average_gap_score});
    try out.print("Total time: {}ms\n", .{summary.total_time_ms});

    if (summary.failed > 0) {
        try out.print("\nFailed items:\n", .{});
        for (summary.results) |r| {
            if (!r.success) {
                try out.print("  - {s}: {s}\n", .{ r.item_path, r.error_message });
            }
        }
    }
}

test "batch - load batch file" {
    const allocator = std.testing.allocator;
    const test_file = try std.fs.cwd().createFile("/tmp/test_batch.txt", .{ .read = true });
    defer test_file.close();
    try test_file.writeAll("file1.exe\n# comment\nfile2.dll | quick\nfile3.sys\n");
    const items = try loadBatchFile(allocator, "/tmp/test_batch.txt");
    defer {
        for (items) |item| allocator.free(item.path);
        allocator.free(items);
    }
    try std.testing.expect(items.len == 3);
    try std.testing.expect(std.mem.eql(u8, items[0].path, "file1.exe"));
}

test "batch - empty batch file" {
    const allocator = std.testing.allocator;
    const test_file = try std.fs.cwd().createFile("/tmp/test_batch_empty.txt", .{ .read = true });
    defer test_file.close();
    const items = try loadBatchFile(allocator, "/tmp/test_batch_empty.txt");
    defer {
        for (items) |item| allocator.free(item.path);
        allocator.free(items);
    }
    try std.testing.expect(items.len == 0);
}
