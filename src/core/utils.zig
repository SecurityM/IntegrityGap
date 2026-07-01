const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;

pub fn readInt(bytes: []const u8, comptime T: type, offset: usize, endian: std.builtin.Endian) !T {
    const info = @typeInfo(T).Int;
    const size = @divExact(info.bits, 8);
    if (offset > bytes.len or bytes.len - offset < size) return error.TruncatedRead;
    return std.mem.readInt(T, bytes[offset..][0..size], endian);
}

pub fn checkedUsize(value: anytype) !usize {
    const wide: u128 = @intCast(value);
    if (wide > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(wide);
}

pub fn readCString(bytes: []const u8, offset: usize) []const u8 {
    if (offset >= bytes.len) return "";
    const tail = bytes[offset..];
    const len = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
    return tail[0..len];
}

pub fn cstrAt(buf: []const u8, offset_value: anytype) []const u8 {
    const offset = checkedUsize(offset_value) catch return "";
    if (offset >= buf.len) return "";
    const tail = buf[offset..];
    const len = std.mem.indexOfScalar(u8, tail, 0) orelse tail.len;
    return tail[0..len];
}

pub fn clamp100(value: f64) f64 {
    if (value < 0) return 0;
    if (value > 100) return 100;
    return value;
}

pub fn squared(value: f64) f64 {
    return value * value;
}

pub fn u64Less(_: void, a: u64, b: u64) bool {
    return a < b;
}

pub fn containsAny(haystack: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (asciiContainsIgnoreCase(haystack, needle)) return true;
    }
    return false;
}

pub fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

pub fn asciiContainsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (asciiEqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

pub fn hexString(bytes: []const u8) ![]u8 {
    const hex = "0123456789abcdef";
    const allocator = std.heap.page_allocator;
    const out = try allocator.alloc(u8, bytes.len * 2 + 1);
    for (bytes, 0..) |byte, i| {
        out[i * 2] = hex[byte >> 4];
        out[i * 2 + 1] = hex[byte & 0x0f];
    }
    out[bytes.len * 2] = 0;
    return out;
}

pub fn readUleb128(bytes: []const u8, offset: *usize) !u64 {
    var result: u64 = 0;
    var shift: usize = 0;
    while (shift < 64) {
        if (offset.* >= bytes.len) return error.TruncatedUleb128;
        const byte = bytes[offset.*];
        offset.* += 1;
        result |= @as(u64, byte & 0x7f) << @intCast(shift);
        if ((byte & 0x80) == 0) return result;
        shift += 7;
    }
    return error.Uleb128Overflow;
}

pub fn readSleb128(bytes: []const u8, offset: *usize) !i64 {
    var result: i64 = 0;
    var shift: usize = 0;
    while (shift < 64) {
        if (offset.* >= bytes.len) return error.TruncatedSleb128;
        const byte = bytes[offset.*];
        offset.* += 1;
        result |= @as(i64, @intCast(byte & 0x7f)) << @intCast(shift);
        shift += 7;
        if ((byte & 0x80) == 0) {
            if (shift < 64 and (byte & 0x40) != 0) {
                result |= -(@as(i64, 1) << @intCast(shift));
            }
            return result;
        }
    }
    return error.Sleb128Overflow;
}

pub fn align_forward(addr: usize, alignment: usize) usize {
    return (addr + alignment - 1) & ~(alignment - 1);
}

pub fn isPowerOfTwo(value: usize) bool {
    return value != 0 and (value & (value - 1)) == 0;
}

pub fn bitCount(value: u64) u8 {
    var v = value;
    var count: u8 = 0;
    while (v != 0) {
        count += @intCast(v & 1);
        v >>= 1;
    }
    return count;
}

pub fn isPrintable(c: u8) bool {
    return c >= 0x20 and c <= 0x7e;
}

pub fn printableSlice(bytes: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    for (bytes[0..end], 0..) |byte, i| {
        if (!isPrintable(byte)) return bytes[0..i];
    }
    return bytes[0..end];
}

pub fn extractStrings(bytes: []const u8, min_len: usize, allocator: Allocator) ![][]const u8 {
    var result = std.ArrayList([]const u8).init(allocator);
    errdefer result.deinit();
    var i: usize = 0;
    while (i < bytes.len) {
        if (isPrintable(bytes[i])) {
            const start = i;
            while (i < bytes.len and isPrintable(bytes[i])) : (i += 1) {}
            if (i - start >= min_len) {
                try result.append(bytes[start..i]);
            }
        } else {
            i += 1;
        }
    }
    return result.toOwnedSlice();
}

pub fn levenshteinDistance(a: []const u8, b: []const u8) usize {
    const m = a.len;
    const n = b.len;
    if (m == 0) return n;
    if (n == 0) return m;
    var prev: [256]usize = [_]usize{0} ** 256;
    var curr: [256]usize = [_]usize{0} ** 256;
    if (n >= 256) return @max(m, n);
    for (0..n + 1) |j| prev[j] = j;
    for (0..m) |i| {
        curr[0] = i + 1;
        for (0..n) |j| {
            const cost: usize = if (a[i] == b[j]) 0 else 1;
            curr[j + 1] = @min(@min(curr[j] + 1, prev[j + 1] + 1), prev[j] + cost);
        }
        @memcpy(prev[0..n+1], curr[0..n+1]);
    }
    return curr[n];
}

pub fn diceCoefficient(a: []const u8, b: []const u8) f64 {
    if (a.len < 2 or b.len < 2) return 0;
    var bigrams_a: usize = 0;
    var bigrams_b: usize = 0;
    var intersection: usize = 0;
    const mask_a = [_]u16{0} ** 256;
    const mask_b = [_]u16{0} ** 256;
    _ = mask_a;
    _ = mask_b;
    var i: usize = 0;
    while (i + 1 < a.len) : (i += 1) {
        bigrams_a += 1;
        for (0..b.len - 1) |j| {
            bigrams_b += 1;
            if (b[j] == a[i] and b[j + 1] == a[i + 1]) {
                intersection += 1;
                break;
            }
        }
    }
    if (bigrams_a + bigrams_b == 0) return 0;
    return 2.0 * @as(f64, @floatFromInt(intersection)) / @as(f64, @floatFromInt(bigrams_a + bigrams_b));
}

pub fn hash32(data: []const u8) u32 {
    var h: u32 = 0x811c9dc5;
    for (data) |byte| {
        h ^= @as(u32, byte);
        h *%= 0x01000193;
    }
    return h;
}

pub fn formatDuration(seconds: i64, buf: []u8) []const u8 {
    if (seconds < 60) {
        _ = std.fmt.bufPrint(buf, "{}s", .{seconds}) catch return "0s";
    } else if (seconds < 3600) {
        _ = std.fmt.bufPrint(buf, "{}m{}s", .{ seconds / 60, seconds % 60 }) catch return "0m";
    } else {
        _ = std.fmt.bufPrint(buf, "{}h{}m", .{ seconds / 3600, (seconds % 3600) / 60 }) catch return "0h";
    }
    return buf[0..std.mem.indexOfScalar(u8, buf, 0) orelse buf.len];
}
