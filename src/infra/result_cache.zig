const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub const CacheEntry = struct {
    file_path: []const u8,
    file_hash: u64,
    result_data: []const u8,
    timestamp: i64,
    ttl_seconds: u64,

    pub fn isExpired(self: *const @This()) bool {
        const now = std.time.timestamp();
        return now > self.timestamp + @as(i64, @intCast(self.ttl_seconds));
    }
};

pub const CacheConfig = struct {
    directory: []const u8 = ".integritygap_cache",
    default_ttl_seconds: u64 = 86400,
    max_entries: usize = 10000,
};

pub const CacheStore = struct {
    allocator: Allocator,
    config: CacheConfig,
    entries: std.StringHashMap(CacheEntry),

    pub fn init(allocator: Allocator, config: CacheConfig) @This() {
        return .{
            .allocator = allocator,
            .config = config,
            .entries = std.StringHashMap(CacheEntry).init(allocator),
        };
    }

    pub fn deinit(self: *@This()) void {
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*.file_path);
            self.allocator.free(entry.value_ptr.*.result_data);
        }
        self.entries.deinit();
    }

    pub fn get(self: *@This(), file_path: []const u8, file_hash: u64) ?[]const u8 {
        const key = self.makeKey(file_path, file_hash) catch return null;
        defer self.allocator.free(key);

        const entry = self.entries.get(key) orelse return null;
        if (entry.isExpired()) {
            const owned = self.entries.get(key);
            if (owned) |e| {
                self.allocator.free(e.result_data);
            }
            _ = self.entries.remove(key);
            self.allocator.free(key);
            self.removeFromDisk(file_path) catch {};
            return null;
        }
        return entry.result_data;
    }

    pub fn set(self: *@This(), file_path: []const u8, file_hash: u64, result_data: []const u8) !void {
        const key = try self.makeKey(file_path, file_hash);

        if (self.entries.count() >= self.config.max_entries) {
            self.evictOldest();
        }

        const entry = CacheEntry{
            .file_path = try self.allocator.dupe(u8, file_path),
            .file_hash = file_hash,
            .result_data = try self.allocator.dupe(u8, result_data),
            .timestamp = std.time.timestamp(),
            .ttl_seconds = self.config.default_ttl_seconds,
        };

        self.entries.put(key, entry) catch {
            self.allocator.free(key);
            self.allocator.free(entry.result_data);
            self.allocator.free(entry.file_path);
            return;
        };

        self.writeToDisk(file_path, file_hash, result_data) catch {};
    }

    pub fn invalidate(self: *@This(), file_path: []const u8) !void {
        var cwd = std.fs.cwd();
        var dir = try cwd.openDir(self.config.directory, .{});
        defer dir.close();
        dir.deleteFile(file_path) catch {};
        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.*.file_path, file_path)) {
                self.allocator.free(entry.value_ptr.*.result_data);
                self.allocator.free(entry.key_ptr.*);
                _ = self.entries.remove(entry.key_ptr.*);
                break;
            }
        }
    }

    pub fn clear(self: *@This()) !void {
        self.entries.clearAndFree();
        var cwd = std.fs.cwd();
        var dir = cwd.openDir(self.config.directory, .{}) catch return;
        defer dir.close();
        var walker = try dir.walk(self.allocator);
        defer walker.deinit();
        while (try walker.next()) |entry| {
            if (entry.kind == .file) {
                dir.deleteFile(entry.basename) catch {};
            }
        }
    }

    fn makeKey(self: *@This(), file_path: []const u8, file_hash: u64) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}_{x}", .{ file_path, file_hash });
    }

    fn evictOldest(self: *@This()) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_time: i64 = std.time.timestamp();

        var it = self.entries.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.timestamp < oldest_time) {
                oldest_time = entry.value_ptr.*.timestamp;
                oldest_key = entry.key_ptr.*;
            }
        }

        if (oldest_key) |key| {
            if (self.entries.get(key)) |e| {
                self.allocator.free(e.result_data);
            }
            self.allocator.free(key);
            _ = self.entries.remove(key);
        }
    }

    fn cachePath(self: *@This(), file_path: []const u8, file_hash: u64, buf: []u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{s}/{s}_{x}.cache", .{ self.config.directory, file_path, file_hash });
    }

    fn writeToDisk(self: *@This(), file_path: []const u8, file_hash: u64, data: []const u8) !void {
        var cwd = std.fs.cwd();
        cwd.makeDir(self.config.directory) catch {};
        var cache_buf: [4096]u8 = undefined;
        const cpath = try self.cachePath(file_path, file_hash, &cache_buf);
        var file = try cwd.createFile(cpath, .{});
        defer file.close();
        try file.writeAll(data);
    }

    fn removeFromDisk(self: *@This(), file_path: []const u8) !void {
        var dir = try std.fs.cwd().openDir(self.config.directory, .{});
        defer dir.close();
        dir.deleteFile(file_path) catch {};
    }
};

pub fn hashFile(_: Allocator, path: []const u8) !u64 {
    var cwd = std.fs.cwd();
    var file = try cwd.openFile(path, .{});
    defer file.close();

    var hasher = std.hash.XxHash64.init(0);
    var buf: [8192]u8 = undefined;

    while (true) {
        const bytes = try file.read(&buf);
        if (bytes == 0) break;
        hasher.update(buf[0..bytes]);
    }

    return hasher.final();
}

test "cache - set and get" {
    const allocator = std.testing.allocator;
    var cache = CacheStore.init(allocator, .{
        .directory = "/tmp/test_cache",
        .default_ttl_seconds = 3600,
    });
    defer cache.deinit();

    try cache.set("test.exe", 0xDEADBEEF, "result data");
    const result = cache.get("test.exe", 0xDEADBEEF);
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.eql(u8, result.?, "result data"));
}

test "cache - miss on different hash" {
    const allocator = std.testing.allocator;
    var cache = CacheStore.init(allocator, .{ .directory = "/tmp/test_cache2", .default_ttl_seconds = 3600 });
    defer cache.deinit();

    try cache.set("test.exe", 0xAAAA, "data");
    const result = cache.get("test.exe", 0xBBBB);
    try std.testing.expect(result == null);
}

test "cache - invalidate" {
    const allocator = std.testing.allocator;
    var cache = CacheStore.init(allocator, .{ .directory = "/tmp/test_cache3", .default_ttl_seconds = 3600 });
    defer cache.deinit();

    try cache.set("test.exe", 0xCAFE, "data");
    try cache.invalidate("test.exe");
    const result = cache.get("test.exe", 0xCAFE);
    try std.testing.expect(result == null);
}
