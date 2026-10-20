const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const enable_file_backend = b.option(
        bool,
        "file-backend",
        "Include the encrypted file backend (enabled by default)",
    ) orelse true;

    const version = b.option([]const u8, "version", "Version string baked into the binary (no 'v' prefix)") orelse "0.0.0-dev";

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    const build_options_module = build_options.createModule();

    const keyring_zig = b.dependency("keyring_zig", .{
        .target = target,
        .@"file-backend" = enable_file_backend,
    });
    const keyring_zig_module = keyring_zig.module("keyring_zig");
    // Reuse keyring-zig's D-Bus module instance. Creating a second module
    // rooted at the same file is rejected by Zig 0.17.
    const secret_service_module = keyring_zig_module.import_table.get("secret_service").?;
    const dbus_module = secret_service_module.import_table.get("dbus").?;

    const exe = b.addExecutable(.{
        .name = "keyring",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    exe.root_module.addImport("keyring_zig", keyring_zig_module);
    exe.root_module.addImport("dbus", dbus_module);
    exe.root_module.addImport("app_build_options", build_options_module);
    linkPlatformDeps(exe.root_module, target.result.os.tag);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run keyring");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    unit_tests.root_module.addImport("keyring_zig", keyring_zig_module);
    unit_tests.root_module.addImport("dbus", dbus_module);
    unit_tests.root_module.addImport("app_build_options", build_options_module);
    linkPlatformDeps(unit_tests.root_module, target.result.os.tag);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}

/// Link the OS frameworks/libraries that `src/keychain.zig` (macOS Keychain via
/// Security.framework) needs into the final binary. These are also pulled in
/// transitively by `keyring_zig`, but the ADO backend references the Security /
/// CoreFoundation symbols directly, so link them explicitly.
fn linkPlatformDeps(module: *std.Build.Module, os_tag: std.Target.Os.Tag) void {
    if (os_tag == .macos) {
        module.linkFramework("Security", .{});
        module.linkFramework("CoreFoundation", .{});
    }
}
