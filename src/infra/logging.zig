const std = @import("std");
const Mutex = std.Thread.Mutex;

pub const LogLevel = enum(u8) {
    debug = 0,
    info = 1,
    warning = 2,
    error = 3,
    critical = 4,
    none = 5,
};

pub const LogConfig = struct {
    level: LogLevel = .info,
    enable_file_logging: bool = true,
    enable_console_logging: bool = true,
    log_file_path: []const u8 = "integritygap.log",
    max_file_size_bytes: u64 = 10 * 1024 * 1024,
    max_backup_files: u8 = 5,
    include_timestamp: bool = true,
    include_level: bool = true,
    include_module: bool = true,
};

var global_config: LogConfig = .{};
var log_mutex: Mutex = .{};
var log_file: ?std.fs.File = null;
var current_file_size: u64 = 0;

pub fn init(config: LogConfig) !void {
    log_mutex.lock();
    defer log_mutex.unlock();
    global_config = config;
    if (config.enable_file_logging and config.log_file_path.len > 0) {
        log_file = try std.fs.cwd().createFile(config.log_file_path, .{ .truncate = true });
        current_file_size = 0;
    }
}

pub fn deinit() void {
    log_mutex.lock();
    defer log_mutex.unlock();
    if (log_file) |*file| {
        file.close();
        log_file = null;
    }
}

pub fn setLevel(level: LogLevel) void {
    log_mutex.lock();
    defer log_mutex.unlock();
    global_config.level = level;
}

fn levelPrefix(level: LogLevel) []const u8 {
    return switch (level) {
        .debug => "DEBUG",
        .info => "INFO",
        .warning => "WARN",
        .error => "ERROR",
        .critical => "CRIT",
        .none => "",
    };
}

pub fn log(level: LogLevel, module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    if (@intFromEnum(level) < @intFromEnum(global_config.level)) return;

    log_mutex.lock();
    defer log_mutex.unlock();

    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    if (global_config.include_timestamp) {
        const ts = std.time.timestamp();
        const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
        const ds = epoch.getDaySeconds();
        const yd = epoch.getYearDay();
        const month_day = yd.day.getMonthDay();
        try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2} ", .{ yd.year, @intFromEnum(month_day.month), month_day.day_index + 1, ds.hours, ds.minutes, ds.seconds });
    }

    if (global_config.include_level) {
        try writer.print("{s:5} ", .{levelPrefix(level)});
    }

    if (global_config.include_module) {
        try writer.print("[{s}] ", .{module});
    }

    try writer.print(fmt, args);
    try writer.writeByte('\n');
    const line = stream.getWritten();

    if (global_config.enable_console_logging) {
        const stderr = std.io.getStdErr().writer();
        stderr.writeAll(line) catch {};
    }

    if (global_config.enable_file_logging) {
        if (log_file) |*file| {
            file.writeAll(line) catch {};
            current_file_size += line.len;
            if (current_file_size >= global_config.max_file_size_bytes) {
                rotateLogFile();
            }
        }
    }
}

fn rotateLogFile() void {
    const log_path = global_config.log_file_path;
    if (log_file) |*file| {
        file.close();
        log_file = null;
    }
    var old_name_buf: [1024]u8 = undefined;
    var new_name_buf: [1024]u8 = undefined;
    for (0..global_config.max_backup_files) |i| {
        const idx = global_config.max_backup_files - i - 1;
        const old_name = if (idx == 0)
            log_path
        else
            std.fmt.bufPrint(&old_name_buf, "{s}.{d}", .{ log_path, idx }) catch continue;
        const new_idx = idx + 1;
        const new_name = std.fmt.bufPrint(&new_name_buf, "{s}.{d}", .{ log_path, new_idx }) catch continue;
        std.fs.rename(std.fs.cwd(), old_name, std.fs.cwd(), new_name) catch {};
    }
    log_file = std.fs.cwd().createFile(log_path, .{ .truncate = true }) catch null;
    current_file_size = 0;
}

pub inline fn debug(module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try log(.debug, module, fmt, args);
}

pub inline fn info(module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try log(.info, module, fmt, args);
}

pub inline fn warn(module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try log(.warning, module, fmt, args);
}

pub inline fn err(module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try log(.error, module, fmt, args);
}

pub inline fn critical(module: []const u8, comptime fmt: []const u8, args: anytype) !void {
    try log(.critical, module, fmt, args);
}

test "logging - level ordering" {
    try std.testing.expect(@intFromEnum(LogLevel.debug) < @intFromEnum(LogLevel.info));
    try std.testing.expect(@intFromEnum(LogLevel.info) < @intFromEnum(LogLevel.warning));
    try std.testing.expect(@intFromEnum(LogLevel.warning) < @intFromEnum(LogLevel.error));
    try std.testing.expect(@intFromEnum(LogLevel.error) < @intFromEnum(LogLevel.critical));
}

test "logging - init and deinit" {
    var config = LogConfig{
        .level = .debug,
        .enable_file_logging = false,
        .log_file_path = "",
    };
    try init(config);
    defer deinit();
    try info("test", "test message", .{});
}
