const std = @import("std");
const types = @import("../types.zig");

const Allocator = types.Allocator;
const AnalysisResult = types.AnalysisResult;

pub const PluginHook = enum {
    pre_analysis,
    post_analysis,
    pre_function,
    post_function,
    pre_report,
    post_report,
    pre_filter,
    post_filter,
};

pub const PluginManifest = struct {
    name: []const u8,
    version: []const u8,
    author: []const u8 = "",
    description: []const u8 = "",
    hooks: []const PluginHook = &[_]PluginHook{},
    api_version: u32 = 1,
};

pub const PluginContext = struct {
    allocator: Allocator,
    manifest: *const PluginManifest,
    analysis_result: ?*AnalysisResult = null,
    user_data: ?*anyopaque = null,
};

pub const Plugin = struct {
    manifest: PluginManifest,
    pre_analysis_fn: ?*const fn (*PluginContext) anyerror!void = null,
    post_analysis_fn: ?*const fn (*PluginContext) anyerror!void = null,
    pre_function_fn: ?*const fn (*PluginContext) anyerror!void = null,
    post_function_fn: ?*const fn (*PluginContext) anyerror!void = null,
    pre_report_fn: ?*const fn (*PluginContext) anyerror!void = null,
    post_report_fn: ?*const fn (*PluginContext) anyerror!void = null,
    pre_filter_fn: ?*const fn (*PluginContext) anyerror!void = null,
    post_filter_fn: ?*const fn (*PluginContext) anyerror!void = null,
};

const hook_count = @typeInfo(PluginHook).Enum.fields.len;

pub const PluginManager = struct {
    allocator: Allocator,
    plugins: std.ArrayList(*Plugin),
    hook_lists: [hook_count]std.ArrayList(*Plugin),

    pub fn init(allocator: Allocator) @This() {
        var hook_lists: [hook_count]std.ArrayList(*Plugin) = undefined;
        for (&hook_lists) |*list| list.* = std.ArrayList(*Plugin).init(allocator);
        return .{
            .allocator = allocator,
            .plugins = std.ArrayList(*Plugin).init(allocator),
            .hook_lists = hook_lists,
        };
    }

    pub fn deinit(self: *@This()) void {
        for (self.plugins.items) |plugin| self.allocator.destroy(plugin);
        self.plugins.deinit();
        for (&self.hook_lists) |*list| list.deinit();
    }

    fn hookIndex(hook: PluginHook) usize {
        return @intFromEnum(hook);
    }

    pub fn register(self: *@This(), plugin: *Plugin) !void {
        try self.plugins.append(plugin);
        inline for (std.meta.fields(PluginHook)) |field| {
            const hook: PluginHook = @enumFromInt(field.value);
            const idx = hookIndex(hook);
            switch (hook) {
                .pre_analysis => if (plugin.pre_analysis_fn != null) try self.hook_lists[idx].append(plugin),
                .post_analysis => if (plugin.post_analysis_fn != null) try self.hook_lists[idx].append(plugin),
                .pre_function => if (plugin.pre_function_fn != null) try self.hook_lists[idx].append(plugin),
                .post_function => if (plugin.post_function_fn != null) try self.hook_lists[idx].append(plugin),
                .pre_report => if (plugin.pre_report_fn != null) try self.hook_lists[idx].append(plugin),
                .post_report => if (plugin.post_report_fn != null) try self.hook_lists[idx].append(plugin),
                .pre_filter => if (plugin.pre_filter_fn != null) try self.hook_lists[idx].append(plugin),
                .post_filter => if (plugin.post_filter_fn != null) try self.hook_lists[idx].append(plugin),
            }
        }
    }

    pub fn unregister(self: *@This(), name: []const u8) void {
        for (self.plugins.items, 0..) |plugin, idx| {
            if (std.mem.eql(u8, plugin.manifest.name, name)) {
                _ = self.plugins.orderedRemove(idx);
                for (&self.hook_lists) |*list| {
                    for (list.items, 0..) |p, pidx| {
                        if (p == plugin) {
                            _ = list.orderedRemove(pidx);
                            break;
                        }
                    }
                }
                self.allocator.destroy(plugin);
                return;
            }
        }
    }

    pub fn executeHook(self: *@This(), hook: PluginHook, context: *PluginContext) !void {
        const idx = hookIndex(hook);
        const list = &self.hook_lists[idx];
        for (list.items) |plugin| {
            const fn_ptr = switch (hook) {
                .pre_analysis => plugin.pre_analysis_fn,
                .post_analysis => plugin.post_analysis_fn,
                .pre_function => plugin.pre_function_fn,
                .post_function => plugin.post_function_fn,
                .pre_report => plugin.pre_report_fn,
                .post_report => plugin.post_report_fn,
                .pre_filter => plugin.pre_filter_fn,
                .post_filter => plugin.post_filter_fn,
            };
            if (fn_ptr) |f| try f(context);
        }
    }

    pub fn loadPlugin(self: *@This(), path: []const u8) !void {
        const lib = std.DynLib.open(path) catch return error.LoadNotSupported;
        const manifest_ptr = lib.lookup(*const PluginManifest, "plugin_manifest") orelse {
            lib.close();
            return error.InvalidPlugin;
        };
        const manifest = manifest_ptr.*;
        const plugin_ptr = try self.allocator.create(Plugin);
        plugin_ptr.* = Plugin{
            .manifest = manifest,
            .pre_analysis_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_pre_analysis"),
            .post_analysis_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_post_analysis"),
            .pre_function_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_pre_function"),
            .post_function_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_post_function"),
            .pre_report_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_pre_report"),
            .post_report_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_post_report"),
            .pre_filter_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_pre_filter"),
            .post_filter_fn = lib.lookup(*const fn (*PluginContext) anyerror!void, "plugin_post_filter"),
        };
        try self.register(plugin_ptr);
    }

    pub fn getPlugin(self: *@This(), name: []const u8) ?*Plugin {
        for (self.plugins.items) |plugin| {
            if (std.mem.eql(u8, plugin.manifest.name, name)) return plugin;
        }
        return null;
    }

    pub fn listPlugins(self: *@This()) []const *Plugin {
        return self.plugins.items;
    }
};

test "plugin - register and lookup" {
    const allocator = std.testing.allocator;
    var manager = PluginManager.init(allocator);
    defer manager.deinit();

    var plugin = try allocator.create(Plugin);
    plugin.* = .{
        .manifest = .{
            .name = "test_plugin",
            .version = "1.0.0",
            .hooks = &[_]PluginHook{.pre_report},
        },
        .pre_report_fn = null,
    };
    try manager.register(plugin);
    try std.testing.expect(manager.getPlugin("test_plugin") != null);
}

test "plugin - unregister" {
    const allocator = std.testing.allocator;
    var manager = PluginManager.init(allocator);
    defer manager.deinit();

    var plugin = try allocator.create(Plugin);
    plugin.* = .{
        .manifest = .{ .name = "remove_me", .version = "1.0.0" },
    };
    try manager.register(plugin);
    try std.testing.expect(manager.getPlugin("remove_me") != null);
    manager.unregister("remove_me");
    try std.testing.expect(manager.getPlugin("remove_me") == null);
}
