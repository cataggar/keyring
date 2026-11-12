//! Conformance test matrix for the typed credential-provider contract (`#40`).
//!
//! Covers:
//! 1. Exhaustive `ProviderChain` fallback vs authoritative halt matrix across
//!    `get`, `login`, and `logout`.
//! 2. Noninteractive retrieval (`InteractionPolicy.never`) enforcement vs
//!    explicit `login` `InteractionPolicy` preservation.
//! 3. Cooperative `Deadline`, atomic cancellation boundaries, and
//!    noninteractive renewal budgets and error propagation.
//! 4. `CredentialKind` separation, input/result validation, and metadata
//!    honesty (`null` vs `&.{}` vs populated `scopes`).
//! 5. Canonical `Target` normalization, scheme/port non-equivalence, bracketed
//!    IPv6 handling, and `serviceKeyAlloc` namespace formatting.
const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const cp = @import("credential_provider.zig");

const ProviderError = cp.ProviderError;
const Operation = cp.Operation;
const InteractionPolicy = cp.InteractionPolicy;
const Target = cp.Target;
const Deadline = cp.Deadline;
const Request = cp.Request;
const CredentialKind = cp.CredentialKind;
const CredentialSecret = cp.CredentialSecret;
const CachePolicy = cp.CachePolicy;
const CredentialResult = cp.CredentialResult;
const LoginInput = cp.LoginInput;
const Provider = cp.Provider;
const ProviderChain = cp.ProviderChain;

const SimClock = struct {
    var current_ms: i64 = 1_700_000_000_000;

    fn nowMs() i64 {
        return current_ms;
    }
};

fn makeFullResult(
    gpa: Allocator,
    username: []const u8,
    secret: []const u8,
    expires_at: ?i64,
    supports_renewal: bool,
) ProviderError!CredentialResult {
    const scopes = try gpa.alloc([]u8, 2);
    errdefer gpa.free(scopes);
    scopes[0] = try gpa.dupe(u8, "read:packages");
    errdefer gpa.free(scopes[0]);
    scopes[1] = try gpa.dupe(u8, "write:packages");
    errdefer gpa.free(scopes[1]);

    const uname_copy = try gpa.dupe(u8, username);
    errdefer gpa.free(uname_copy);
    const sec_copy = try gpa.dupe(u8, secret);
    errdefer gpa.free(sec_copy);
    const acct_copy = try gpa.dupe(u8, username);
    errdefer gpa.free(acct_copy);
    const aud_copy = try gpa.dupe(u8, "https://registry.example.com");
    errdefer gpa.free(aud_copy);

    return .{
        .secret = .{
            .basic = .{
                .username = uname_copy,
                .secret = sec_copy,
            },
        },
        .account = acct_copy,
        .expires_at = expires_at,
        .cache_policy = if (expires_at != null) .until_expiration else .eternal,
        .audience = aud_copy,
        .scopes = scopes,
        .supports_noninteractive_renewal = supports_renewal,
    };
}

// ---------------------------------------------------------------------------
// 1. Exhaustive ProviderChain Error & Fallback Matrix (get, login, logout)
// ---------------------------------------------------------------------------

test "conformance matrix: ProviderChain fallback vs authoritative halt across get, login, and logout" {
    const gpa = testing.allocator;
    const target = try Target.parseAlloc(gpa, "https://registry.example.com", .{});
    defer target.deinit(gpa);

    const MatrixNode = struct {
        outcome: ?ProviderError = null,
        identity: []const u8 = "fallback-user",
        calls: usize = 0,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.outcome) |err| return err;
            return .{
                .secret = .{
                    .basic = .{
                        .username = try alloc.dupe(u8, self.identity),
                        .secret = try alloc.dupe(u8, "fallback-secret"),
                    },
                },
                .account = try alloc.dupe(u8, self.identity),
            };
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, _: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.outcome) |err| return err;
            return .{
                .secret = .{
                    .basic = .{
                        .username = try alloc.dupe(u8, self.identity),
                        .secret = try alloc.dupe(u8, "fallback-login-secret"),
                    },
                },
                .account = try alloc.dupe(u8, self.identity),
            };
        }

        fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            if (self.outcome) |err| return err;
        }

        fn asProvider(self: *@This(), name: []const u8) Provider {
            return .{
                .name = name,
                .ctx = self,
                .getFn = get,
                .loginFn = login,
                .logoutFn = logout,
            };
        }
    };

    // 1a. Fallback-eligible errors MUST advance from primary to secondary across get, login, logout.
    const fallback_errors = [_]ProviderError{
        error.UnsupportedTarget,
        error.UnsupportedOperation,
        error.CredentialNotFound,
    };

    for (fallback_errors) |fb_err| {
        // get
        {
            var primary: MatrixNode = .{ .outcome = fb_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            const res = try chain.get(gpa, .{ .target = target, .operation = .get });
            defer res.deinit(gpa);

            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
            try testing.expectEqualStrings("fallback-user", res.account.?);
            try testing.expectEqualStrings("fallback-user", res.secret.basic.username);
        }

        // login
        {
            var primary: MatrixNode = .{ .outcome = fb_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            const res = try chain.login(gpa, .{
                .request = .{ .target = target, .operation = .login, .interaction = .if_available },
            });
            defer res.deinit(gpa);

            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
            try testing.expectEqualStrings("fallback-user", res.account.?);
            try testing.expectEqualStrings("fallback-user", res.secret.basic.username);
        }

        // logout
        {
            var primary: MatrixNode = .{ .outcome = fb_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try chain.logout(gpa, .{ .target = target, .operation = .logout });

            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
        }
    }

    // 1b. When primary returns CredentialNotFound and secondary returns UnsupportedTarget,
    // the chain preserves CredentialNotFound (and likewise across fallback rank combinations).
    const RankCase = struct {
        first: ProviderError,
        second: ProviderError,
        expected: ProviderError,
    };
    const rank_cases = [_]RankCase{
        .{
            .first = error.CredentialNotFound,
            .second = error.UnsupportedTarget,
            .expected = error.CredentialNotFound,
        },
        .{
            .first = error.UnsupportedTarget,
            .second = error.CredentialNotFound,
            .expected = error.CredentialNotFound,
        },
        .{
            .first = error.CredentialNotFound,
            .second = error.UnsupportedOperation,
            .expected = error.CredentialNotFound,
        },
        .{
            .first = error.UnsupportedOperation,
            .second = error.UnsupportedTarget,
            .expected = error.UnsupportedOperation,
        },
        .{
            .first = error.UnsupportedTarget,
            .second = error.UnsupportedTarget,
            .expected = error.UnsupportedTarget,
        },
    };

    for (rank_cases) |rc| {
        // get
        {
            var primary: MatrixNode = .{ .outcome = rc.first };
            var secondary: MatrixNode = .{ .outcome = rc.second };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(rc.expected, chain.get(gpa, .{ .target = target }));
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
        }

        // login
        {
            var primary: MatrixNode = .{ .outcome = rc.first };
            var secondary: MatrixNode = .{ .outcome = rc.second };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(
                rc.expected,
                chain.login(gpa, .{ .request = .{ .target = target, .operation = .login } }),
            );
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
        }

        // logout
        {
            var primary: MatrixNode = .{ .outcome = rc.first };
            var secondary: MatrixNode = .{ .outcome = rc.second };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(
                rc.expected,
                chain.logout(gpa, .{ .target = target, .operation = .logout }),
            );
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 1), secondary.calls);
        }
    }

    // 1c. Every non-fallback error from primary MUST halt immediately (secondary_calls == 0)
    // and surface primary's exact error across get, login, and logout.
    const halting_errors = [_]ProviderError{
        error.ReauthenticationRequired,
        error.StorageUnavailable,
        error.StorageLocked,
        error.AccessDenied,
        error.Cancelled,
        error.DeadlineExceeded,
        error.InvalidInput,
        error.StorageFailure,
        error.OutOfMemory,
    };

    for (halting_errors) |halt_err| {
        // get
        {
            var primary: MatrixNode = .{ .outcome = halt_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(halt_err, chain.get(gpa, .{ .target = target }));
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 0), secondary.calls);
        }

        // login
        {
            var primary: MatrixNode = .{ .outcome = halt_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(
                halt_err,
                chain.login(gpa, .{ .request = .{ .target = target, .operation = .login } }),
            );
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 0), secondary.calls);
        }

        // logout
        {
            var primary: MatrixNode = .{ .outcome = halt_err, .identity = "primary-user" };
            var secondary: MatrixNode = .{ .outcome = null, .identity = "fallback-user" };
            const providers = [_]Provider{
                primary.asProvider("primary"),
                secondary.asProvider("secondary"),
            };
            const chain: ProviderChain = .{ .providers = &providers };

            try testing.expectError(
                halt_err,
                chain.logout(gpa, .{ .target = target, .operation = .logout }),
            );
            try testing.expectEqual(@as(usize, 1), primary.calls);
            try testing.expectEqual(@as(usize, 0), secondary.calls);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Noninteractive Retrieval & Kubernetes-Style InteractionPolicy Enforcement
// ---------------------------------------------------------------------------

test "conformance matrix: noninteractive get enforcement vs explicit login InteractionPolicy" {
    const gpa = testing.allocator;
    const target = try Target.parseAlloc(gpa, "https://ghcr.io", .{});
    defer target.deinit(gpa);

    const GetPolicyRecorder = struct {
        saw_get_interaction: ?InteractionPolicy = null,
        saw_get_operation: ?Operation = null,
        saw_renew_interaction: ?InteractionPolicy = null,
        saw_renew_operation: ?Operation = null,
        saw_account: ?[]const u8 = null,
        saw_audience: ?[]const u8 = null,
        saw_scopes_len: usize = 0,
        return_expired: bool = false,

        fn get(ctx: ?*anyopaque, alloc: Allocator, req: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.saw_get_interaction = req.interaction;
            self.saw_get_operation = req.operation;
            self.saw_account = req.account;
            self.saw_audience = req.audience;
            self.saw_scopes_len = req.scopes.len;

            // Interactive prompting must always be forbidden inside getFn.
            if (req.interaction.allowsInteractive(false) or req.interaction.allowsInteractive(true)) {
                return error.InvalidInput;
            }

            if (self.return_expired) {
                return .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "expired-bearer") },
                    .expires_at = 1_000,
                    .cache_policy = .until_expiration,
                    .supports_noninteractive_renewal = true,
                };
            }
            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "fresh-bearer") },
            };
        }

        fn renew(
            ctx: ?*anyopaque,
            alloc: Allocator,
            req: Request,
            _: *const CredentialResult,
        ) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.saw_renew_interaction = req.interaction;
            self.saw_renew_operation = req.operation;

            // Interactive prompting must always be forbidden inside renewNoninteractiveFn.
            if (req.interaction.allowsInteractive(false) or req.interaction.allowsInteractive(true)) {
                return error.InvalidInput;
            }

            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "renewed-bearer") },
                .expires_at = 5_000,
                .cache_policy = .until_expiration,
                .supports_noninteractive_renewal = true,
            };
        }
    };

    const UnsupportedStub = struct {
        fn get(_: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
            return error.UnsupportedTarget;
        }
        fn login(_: ?*anyopaque, _: Allocator, _: LoginInput) ProviderError!CredentialResult {
            return error.UnsupportedTarget;
        }
    };

    SimClock.current_ms = 2_000_000; // 2_000s > 1_000s

    const caller_policies = [_]InteractionPolicy{ .never, .if_available, .always };
    const req_scopes = [_][]const u8{"read:packages"};

    for (caller_policies) |policy| {
        // Direct Provider.executeGet (including renewal path)
        {
            var rec: GetPolicyRecorder = .{ .return_expired = true };
            const provider: Provider = .{
                .name = "recorder",
                .ctx = &rec,
                .getFn = GetPolicyRecorder.get,
                .renewNoninteractiveFn = GetPolicyRecorder.renew,
            };

            const res = try provider.executeGet(gpa, .{
                .target = target,
                .operation = .get,
                .account = "octocat",
                .audience = "https://ghcr.io",
                .scopes = &req_scopes,
                .interaction = policy,
                .deadline = .{ .now_ms_fn = SimClock.nowMs },
            });
            defer res.deinit(gpa);

            try testing.expectEqual(InteractionPolicy.never, rec.saw_get_interaction.?);
            try testing.expectEqual(Operation.get, rec.saw_get_operation.?);
            try testing.expectEqual(InteractionPolicy.never, rec.saw_renew_interaction.?);
            try testing.expectEqual(Operation.get, rec.saw_renew_operation.?);
            try testing.expectEqualStrings("octocat", rec.saw_account.?);
            try testing.expectEqualStrings("https://ghcr.io", rec.saw_audience.?);
            try testing.expectEqual(@as(usize, 1), rec.saw_scopes_len);
            try testing.expectEqualStrings("renewed-bearer", res.secret.bearer_token);
        }

        // ProviderChain.get (routing past an unsupported primary provider)
        {
            var rec: GetPolicyRecorder = .{ .return_expired = true };
            const providers = [_]Provider{
                .{ .name = "unsupported", .getFn = UnsupportedStub.get },
                .{
                    .name = "recorder",
                    .ctx = &rec,
                    .getFn = GetPolicyRecorder.get,
                    .renewNoninteractiveFn = GetPolicyRecorder.renew,
                },
            };
            const chain: ProviderChain = .{ .providers = &providers };

            const res = try chain.get(gpa, .{
                .target = target,
                .operation = .get,
                .interaction = policy,
                .deadline = .{ .now_ms_fn = SimClock.nowMs },
            });
            defer res.deinit(gpa);

            try testing.expectEqual(InteractionPolicy.never, rec.saw_get_interaction.?);
            try testing.expectEqual(InteractionPolicy.never, rec.saw_renew_interaction.?);
            try testing.expectEqualStrings("renewed-bearer", res.secret.bearer_token);
        }
    }

    // Provider.executeLogin and ProviderChain.login preserve input.request.interaction
    // so explicit login providers can enforce .allowsInteractive(tty_available).
    const LoginPolicyGate = struct {
        tty_available: bool,
        saw_interaction: ?InteractionPolicy = null,

        fn get(_: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
            return error.CredentialNotFound;
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, input: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.saw_interaction = input.request.interaction;
            if (!input.request.interaction.allowsInteractive(self.tty_available)) {
                return error.ReauthenticationRequired;
            }
            return .{
                .secret = .{ .bearer_token = try alloc.dupe(u8, "interactive-login-token") },
            };
        }
    };

    const LoginExpectation = struct {
        policy: InteractionPolicy,
        tty_available: bool,
        should_succeed: bool,
    };
    const login_matrix = [_]LoginExpectation{
        .{ .policy = .never, .tty_available = false, .should_succeed = false },
        .{ .policy = .never, .tty_available = true, .should_succeed = false },
        .{ .policy = .if_available, .tty_available = false, .should_succeed = false },
        .{ .policy = .if_available, .tty_available = true, .should_succeed = true },
        .{ .policy = .always, .tty_available = false, .should_succeed = true },
        .{ .policy = .always, .tty_available = true, .should_succeed = true },
    };

    for (login_matrix) |tc| {
        // Direct Provider.executeLogin
        {
            var gate: LoginPolicyGate = .{ .tty_available = tc.tty_available };
            const provider: Provider = .{
                .name = "login-gate",
                .ctx = &gate,
                .getFn = LoginPolicyGate.get,
                .loginFn = LoginPolicyGate.login,
            };

            const login_input: LoginInput = .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .interaction = tc.policy,
                },
            };

            if (tc.should_succeed) {
                const res = try provider.executeLogin(gpa, login_input);
                defer res.deinit(gpa);
                try testing.expectEqualStrings("interactive-login-token", res.secret.bearer_token);
            } else {
                try testing.expectError(
                    error.ReauthenticationRequired,
                    provider.executeLogin(gpa, login_input),
                );
            }
            try testing.expectEqual(tc.policy, gate.saw_interaction.?);
        }

        // ProviderChain.login
        {
            var gate: LoginPolicyGate = .{ .tty_available = tc.tty_available };
            const providers = [_]Provider{
                .{
                    .name = "unsupported",
                    .getFn = UnsupportedStub.get,
                    .loginFn = UnsupportedStub.login,
                },
                .{
                    .name = "login-gate",
                    .ctx = &gate,
                    .getFn = LoginPolicyGate.get,
                    .loginFn = LoginPolicyGate.login,
                },
            };
            const chain: ProviderChain = .{ .providers = &providers };

            const login_input: LoginInput = .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .interaction = tc.policy,
                },
            };

            if (tc.should_succeed) {
                const res = try chain.login(gpa, login_input);
                defer res.deinit(gpa);
                try testing.expectEqualStrings("interactive-login-token", res.secret.bearer_token);
            } else {
                try testing.expectError(error.ReauthenticationRequired, chain.login(gpa, login_input));
            }
            try testing.expectEqual(tc.policy, gate.saw_interaction.?);
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Deadline, Cancellation, and Noninteractive Renewal Budget Matrix
// ---------------------------------------------------------------------------

test "conformance matrix: deadline, atomic cancellation, and noninteractive renewal budgets" {
    const gpa = testing.allocator;
    const target = try Target.parseAlloc(gpa, "https://packages.example.com:8443", .{});
    defer target.deinit(gpa);

    const RenewalHarness = struct {
        expired_at: i64 = 1_500,
        supports_renewal: bool = true,
        advance_ms_on_renew: i64 = 0,
        renewed_expires_at: ?i64 = 3_000,
        renew_err: ?ProviderError = null,
        trip_cancel_on_renew: ?*std.atomic.Value(bool) = null,
        get_calls: usize = 0,
        renew_calls: usize = 0,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.get_calls += 1;
            return makeFullResult(
                alloc,
                "primary-user",
                "expired-secret",
                self.expired_at,
                self.supports_renewal,
            );
        }

        fn renew(
            ctx: ?*anyopaque,
            alloc: Allocator,
            req: Request,
            expired: *const CredentialResult,
        ) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.renew_calls += 1;

            if (req.interaction != .never) return error.InvalidInput;
            if (!std.mem.eql(u8, expired.secret.basic.username, "primary-user")) {
                return error.StorageFailure;
            }
            if (!std.mem.eql(u8, expired.secret.basic.secret, "expired-secret")) {
                return error.StorageFailure;
            }

            SimClock.current_ms += self.advance_ms_on_renew;
            if (self.trip_cancel_on_renew) |flag| {
                flag.store(true, .release);
            }
            if (self.renew_err) |err| return err;

            return makeFullResult(
                alloc,
                "primary-user",
                "renewed-secret",
                self.renewed_expires_at,
                true,
            );
        }
    };

    const SecondarySentinel = struct {
        calls: usize = 0,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            return makeFullResult(alloc, "fallback-user", "fallback-secret", null, false);
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, _: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            return makeFullResult(alloc, "fallback-user", "fallback-secret", null, false);
        }

        fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
        }
    };

    // 3a. Expired + supports_noninteractive_renewal = true + completes before deadline_ms
    // -> returns renewed credential and frees intermediate expired credential without leaks.
    {
        SimClock.current_ms = 1_500_000; // 1_500s == expired_at
        var primary: RenewalHarness = .{
            .expired_at = 1_500,
            .supports_renewal = true,
            .advance_ms_on_renew = 400, // 1_500_400 < 1_501_000
            .renewed_expires_at = 3_000,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        const res = try chain.get(gpa, .{
            .target = target,
            .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
        });
        defer res.deinit(gpa);

        try testing.expectEqual(@as(usize, 1), primary.get_calls);
        try testing.expectEqual(@as(usize, 1), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
        try testing.expectEqualStrings("renewed-secret", res.secret.basic.secret);
        try testing.expectEqual(@as(?i64, 3_000), res.expires_at);
    }

    // 3b. Expired + renewNoninteractiveFn advancing simulated clock TO or PAST deadline_ms
    // -> frees both intermediate and renewed credentials and returns DeadlineExceeded.
    for ([_]i64{ 1_000, 2_500 }) |advance_ms| {
        SimClock.current_ms = 1_500_000;
        var primary: RenewalHarness = .{
            .expired_at = 1_500,
            .supports_renewal = true,
            .advance_ms_on_renew = advance_ms, // 1_501_000 (== deadline) and 1_502_500 (> deadline)
            .renewed_expires_at = 3_000,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.DeadlineExceeded,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // 3c. Expired + renewNoninteractiveFn returning a credential STILL expired at nowSeconds()
    // (both == nowSeconds() and < nowSeconds()) -> frees it and returns ReauthenticationRequired.
    for ([_]i64{ 1_500, 1_499 }) |still_expired_at| {
        SimClock.current_ms = 1_500_250; // nowSeconds() == 1_500
        var primary: RenewalHarness = .{
            .expired_at = 1_400,
            .supports_renewal = true,
            .advance_ms_on_renew = 100, // nowSeconds() remains 1_500 < deadline 1_505_000ms
            .renewed_expires_at = still_expired_at,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.ReauthenticationRequired,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_505_000 },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // 3d. Expired + renewNoninteractiveFn failing with StorageLocked or AccessDenied
    // -> propagates StorageLocked / AccessDenied directly (never masked as CredentialNotFound).
    for ([_]ProviderError{
        error.StorageLocked,
        error.AccessDenied,
        error.StorageUnavailable,
        error.StorageFailure,
    }) |direct_err| {
        SimClock.current_ms = 1_600_000;
        var primary: RenewalHarness = .{
            .expired_at = 1_500,
            .supports_renewal = true,
            .renew_err = direct_err,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            direct_err,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_605_000 },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // 3e. Expired + supports_noninteractive_renewal = false (even when renewNoninteractiveFn is non-null)
    // -> renew_calls == 0, returns ReauthenticationRequired, secondary_calls == 0.
    {
        SimClock.current_ms = 1_600_000;
        var primary: RenewalHarness = .{
            .expired_at = 1_500,
            .supports_renewal = false,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew, // non-null!
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.ReauthenticationRequired,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_605_000 },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.get_calls);
        try testing.expectEqual(@as(usize, 0), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // 3f. Atomic cancellation tripped inside provider #1 right before returning CredentialNotFound
    // -> ProviderChain detects cancellation at the boundary and returns error.Cancelled
    // without invoking provider #2 (secondary_calls == 0), across get, login, and logout.
    const CancellingMissProvider = struct {
        cancel_flag: *std.atomic.Value(bool),
        calls: usize = 0,

        fn get(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.cancel_flag.store(true, .release);
            return error.CredentialNotFound;
        }

        fn login(ctx: ?*anyopaque, _: Allocator, _: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.cancel_flag.store(true, .release);
            return error.CredentialNotFound;
        }

        fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.calls += 1;
            self.cancel_flag.store(true, .release);
            return error.CredentialNotFound;
        }
    };

    // get boundary cancellation
    {
        SimClock.current_ms = 1_500_000;
        var cancelled = std.atomic.Value(bool).init(false);
        var primary: CancellingMissProvider = .{ .cancel_flag = &cancelled };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{ .name = "primary", .ctx = &primary, .getFn = CancellingMissProvider.get },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.Cancelled,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{
                    .now_ms_fn = SimClock.nowMs,
                    .deadline_ms = 1_510_000,
                    .cancelled = &cancelled,
                },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // login boundary cancellation
    {
        SimClock.current_ms = 1_500_000;
        var cancelled = std.atomic.Value(bool).init(false);
        var primary: CancellingMissProvider = .{ .cancel_flag = &cancelled };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = CancellingMissProvider.get,
                .loginFn = CancellingMissProvider.login,
            },
            .{
                .name = "secondary",
                .ctx = &secondary,
                .getFn = SecondarySentinel.get,
                .loginFn = SecondarySentinel.login,
            },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.Cancelled,
            chain.login(gpa, .{
                .request = .{
                    .target = target,
                    .operation = .login,
                    .deadline = .{
                        .now_ms_fn = SimClock.nowMs,
                        .deadline_ms = 1_510_000,
                        .cancelled = &cancelled,
                    },
                },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // logout boundary cancellation
    {
        SimClock.current_ms = 1_500_000;
        var cancelled = std.atomic.Value(bool).init(false);
        var primary: CancellingMissProvider = .{ .cancel_flag = &cancelled };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = CancellingMissProvider.get,
                .logoutFn = CancellingMissProvider.logout,
            },
            .{
                .name = "secondary",
                .ctx = &secondary,
                .getFn = SecondarySentinel.get,
                .logoutFn = SecondarySentinel.logout,
            },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.Cancelled,
            chain.logout(gpa, .{
                .target = target,
                .operation = .logout,
                .deadline = .{
                    .now_ms_fn = SimClock.nowMs,
                    .deadline_ms = 1_510_000,
                    .cancelled = &cancelled,
                },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // Cancellation tripped during renewNoninteractiveFn (even after deadline also passes)
    // frees both intermediate and renewed credentials and surfaces error.Cancelled.
    {
        SimClock.current_ms = 1_500_000;
        var cancelled = std.atomic.Value(bool).init(false);
        var primary: RenewalHarness = .{
            .expired_at = 1_500,
            .supports_renewal = true,
            .advance_ms_on_renew = 2_000, // also past deadline_ms; Cancelled must still win
            .trip_cancel_on_renew = &cancelled,
        };
        var secondary: SecondarySentinel = .{};
        const providers = [_]Provider{
            .{
                .name = "primary",
                .ctx = &primary,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            },
            .{ .name = "secondary", .ctx = &secondary, .getFn = SecondarySentinel.get },
        };
        const chain: ProviderChain = .{ .providers = &providers };

        try testing.expectError(
            error.Cancelled,
            chain.get(gpa, .{
                .target = target,
                .deadline = .{
                    .now_ms_fn = SimClock.nowMs,
                    .deadline_ms = 1_501_000,
                    .cancelled = &cancelled,
                },
            }),
        );
        try testing.expectEqual(@as(usize, 1), primary.renew_calls);
        try testing.expectEqual(@as(usize, 0), secondary.calls);
    }

    // 3f-single. Single-provider ProviderChain and direct Provider.executeGet / executeLogin /
    // executeLogout + renewNoninteractiveFn surface Cancelled / DeadlineExceeded even when the
    // callback returns error.CredentialNotFound after tripping cancellation or exceeding deadline_ms.
    {
        const ErrorBudgetProvider = struct {
            advance_ms: i64 = 0,
            cancel_flag: ?*std.atomic.Value(bool) = null,
            err_to_return: ProviderError = error.CredentialNotFound,

            fn trip(self: *@This()) ProviderError {
                SimClock.current_ms += self.advance_ms;
                if (self.cancel_flag) |flag| {
                    flag.store(true, .release);
                }
                return self.err_to_return;
            }

            fn get(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!CredentialResult {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                return self.trip();
            }

            fn login(ctx: ?*anyopaque, _: Allocator, _: LoginInput) ProviderError!CredentialResult {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                return self.trip();
            }

            fn logout(ctx: ?*anyopaque, _: Allocator, _: Request) ProviderError!void {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                return self.trip();
            }
        };

        // Cancelled on error path: direct Provider + single-provider ProviderChain
        {
            var cancelled = std.atomic.Value(bool).init(false);
            var ebp: ErrorBudgetProvider = .{ .cancel_flag = &cancelled };
            const prov: Provider = .{
                .name = "single-cancel",
                .ctx = &ebp,
                .getFn = ErrorBudgetProvider.get,
                .loginFn = ErrorBudgetProvider.login,
                .logoutFn = ErrorBudgetProvider.logout,
            };
            const single_chain: ProviderChain = .{ .providers = &.{prov} };

            SimClock.current_ms = 1_500_000;
            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                prov.executeGet(gpa, .{
                    .target = target,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                }),
            );

            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                single_chain.get(gpa, .{
                    .target = target,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                }),
            );

            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                prov.executeLogin(gpa, .{
                    .request = .{
                        .target = target,
                        .operation = .login,
                        .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                    },
                }),
            );

            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                single_chain.login(gpa, .{
                    .request = .{
                        .target = target,
                        .operation = .login,
                        .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                    },
                }),
            );

            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                prov.executeLogout(gpa, .{
                    .target = target,
                    .operation = .logout,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                }),
            );

            cancelled.store(false, .release);
            try testing.expectError(
                error.Cancelled,
                single_chain.logout(gpa, .{
                    .target = target,
                    .operation = .logout,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000, .cancelled = &cancelled },
                }),
            );
        }

        // DeadlineExceeded on error path: direct Provider + single-provider ProviderChain
        {
            var ebp: ErrorBudgetProvider = .{ .advance_ms = 2_000 };
            const prov: Provider = .{
                .name = "single-deadline",
                .ctx = &ebp,
                .getFn = ErrorBudgetProvider.get,
                .loginFn = ErrorBudgetProvider.login,
                .logoutFn = ErrorBudgetProvider.logout,
            };
            const single_chain: ProviderChain = .{ .providers = &.{prov} };

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                prov.executeGet(gpa, .{
                    .target = target,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                }),
            );

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                single_chain.get(gpa, .{
                    .target = target,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                }),
            );

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                prov.executeLogin(gpa, .{
                    .request = .{
                        .target = target,
                        .operation = .login,
                        .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                    },
                }),
            );

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                single_chain.login(gpa, .{
                    .request = .{
                        .target = target,
                        .operation = .login,
                        .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                    },
                }),
            );

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                prov.executeLogout(gpa, .{
                    .target = target,
                    .operation = .logout,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                }),
            );

            SimClock.current_ms = 1_500_000;
            try testing.expectError(
                error.DeadlineExceeded,
                single_chain.logout(gpa, .{
                    .target = target,
                    .operation = .logout,
                    .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_501_000 },
                }),
            );
        }

        // renewNoninteractiveFn returning error.CredentialNotFound after cancellation or deadline
        // surfaces Cancelled / DeadlineExceeded instead of mapping to ReauthenticationRequired.
        {
            SimClock.current_ms = 1_500_000;
            var cancelled = std.atomic.Value(bool).init(false);
            var cancel_renew: RenewalHarness = .{
                .expired_at = 1_500,
                .supports_renewal = true,
                .trip_cancel_on_renew = &cancelled,
                .renew_err = error.CredentialNotFound,
            };
            const cancel_prov: Provider = .{
                .name = "renew-cancel-on-err",
                .ctx = &cancel_renew,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            };
            const single_cancel_chain: ProviderChain = .{ .providers = &.{cancel_prov} };

            try testing.expectError(
                error.Cancelled,
                single_cancel_chain.get(gpa, .{
                    .target = target,
                    .deadline = .{
                        .now_ms_fn = SimClock.nowMs,
                        .deadline_ms = 1_510_000,
                        .cancelled = &cancelled,
                    },
                }),
            );

            SimClock.current_ms = 1_500_000;
            var deadline_renew: RenewalHarness = .{
                .expired_at = 1_500,
                .supports_renewal = true,
                .advance_ms_on_renew = 2_000,
                .renew_err = error.CredentialNotFound,
            };
            const deadline_prov: Provider = .{
                .name = "renew-deadline-on-err",
                .ctx = &deadline_renew,
                .getFn = RenewalHarness.get,
                .renewNoninteractiveFn = RenewalHarness.renew,
            };
            const single_deadline_chain: ProviderChain = .{ .providers = &.{deadline_prov} };

            try testing.expectError(
                error.DeadlineExceeded,
                single_deadline_chain.get(gpa, .{
                    .target = target,
                    .deadline = .{
                        .now_ms_fn = SimClock.nowMs,
                        .deadline_ms = 1_501_000,
                    },
                }),
            );
        }
    }

    // 3g. Exhaustive OOM allocation-failure sweep across renewal + chain execution.
    const oomRenewalRun = struct {
        fn run(alloc: Allocator, tgt: Target) !void {
            SimClock.current_ms = 1_500_000;
            var primary: RenewalHarness = .{
                .expired_at = 1_500,
                .supports_renewal = true,
                .advance_ms_on_renew = 100,
                .renewed_expires_at = 3_000,
            };
            const providers = [_]Provider{
                .{
                    .name = "primary",
                    .ctx = &primary,
                    .getFn = RenewalHarness.get,
                    .renewNoninteractiveFn = RenewalHarness.renew,
                },
            };
            const chain: ProviderChain = .{ .providers = &providers };
            const res = try chain.get(alloc, .{
                .target = tgt,
                .deadline = .{ .now_ms_fn = SimClock.nowMs, .deadline_ms = 1_510_000 },
            });
            defer res.deinit(alloc);

            const cloned = try res.clone(alloc);
            defer cloned.deinit(alloc);
        }
    }.run;

    try testing.checkAllAllocationFailures(gpa, oomRenewalRun, .{target});
}

// ---------------------------------------------------------------------------
// 4. Credential Kind Separation & Metadata Honesty
// ---------------------------------------------------------------------------

test "conformance matrix: credential kind separation, validation, and metadata honesty" {
    const gpa = testing.allocator;
    const target = try Target.parseAlloc(gpa, "https://registry.example.com", .{});
    defer target.deinit(gpa);

    const EchoProvider = struct {
        template: *const CredentialResult,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.template.clone(alloc);
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, _: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.template.clone(alloc);
        }
    };

    // 4a. basic, bearer_token, and identity_token remain distinct variants through
    // Provider.executeGet, Provider.executeLogin, ProviderChain, and CredentialResult.clone.
    {
        const basic_seed: CredentialResult = .{
            .secret = .{
                .basic = .{
                    .username = try gpa.dupe(u8, "registry-user"),
                    .secret = try gpa.dupe(u8, "s3cr3t!@#"),
                },
            },
        };
        defer basic_seed.deinit(gpa);

        const bearer_seed: CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9") },
        };
        defer bearer_seed.deinit(gpa);

        const identity_seed: CredentialResult = .{
            .secret = .{ .identity_token = try gpa.dupe(u8, "oauth2-refresh-or-oidc-identity-token") },
        };
        defer identity_seed.deinit(gpa);

        const VariantCheck = struct {
            seed: *const CredentialResult,
            expected_kind: CredentialKind,
        };
        const checks = [_]VariantCheck{
            .{ .seed = &basic_seed, .expected_kind = .basic },
            .{ .seed = &bearer_seed, .expected_kind = .bearer_token },
            .{ .seed = &identity_seed, .expected_kind = .identity_token },
        };

        for (checks) |chk| {
            var echo: EchoProvider = .{ .template = chk.seed };
            const provider: Provider = .{
                .name = "echo",
                .ctx = &echo,
                .getFn = EchoProvider.get,
                .loginFn = EchoProvider.login,
            };
            const providers = [_]Provider{provider};
            const chain: ProviderChain = .{ .providers = &providers };

            const got = try chain.get(gpa, .{ .target = target });
            defer got.deinit(gpa);
            try testing.expectEqual(chk.expected_kind, got.secret.kind());

            const logged_in = try chain.login(gpa, .{
                .request = .{ .target = target, .operation = .login },
            });
            defer logged_in.deinit(gpa);
            try testing.expectEqual(chk.expected_kind, logged_in.secret.kind());

            const cloned = try got.clone(gpa);
            defer cloned.deinit(gpa);
            try testing.expectEqual(chk.expected_kind, cloned.secret.kind());

            switch (chk.expected_kind) {
                .basic => {
                    try testing.expectEqualStrings("registry-user", cloned.secret.basic.username);
                    try testing.expectEqualStrings("s3cr3t!@#", cloned.secret.basic.secret);
                },
                .bearer_token => {
                    try testing.expectEqualStrings(
                        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
                        cloned.secret.bearer_token,
                    );
                },
                .identity_token => {
                    try testing.expectEqualStrings(
                        "oauth2-refresh-or-oidc-identity-token",
                        cloned.secret.identity_token,
                    );
                },
            }
        }
    }

    // 4b. Invalid combinations fail with error.InvalidInput and free provider-allocated results
    // cleanly without memory leaks.
    const InvalidFactory = enum {
        empty_basic_username,
        empty_basic_secret,
        empty_bearer_token,
        empty_identity_token,
        ctrl_in_username_lf,
        ctrl_in_username_del,
        ctrl_in_account,
        empty_account,
        ctrl_in_audience,
        empty_audience,
        ctrl_in_scope,
        empty_scope,
        nul_in_basic_secret,
        nul_in_bearer_token,
        nul_in_identity_token,
        until_expiration_without_expires_at,

        fn build(self: @This(), alloc: Allocator) ProviderError!CredentialResult {
            return switch (self) {
                .empty_basic_username => .{
                    .secret = .{
                        .basic = .{
                            .username = try alloc.dupe(u8, ""),
                            .secret = try alloc.dupe(u8, "valid-secret"),
                        },
                    },
                },
                .empty_basic_secret => .{
                    .secret = .{
                        .basic = .{
                            .username = try alloc.dupe(u8, "alice"),
                            .secret = try alloc.dupe(u8, ""),
                        },
                    },
                },
                .empty_bearer_token => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "") },
                },
                .empty_identity_token => .{
                    .secret = .{ .identity_token = try alloc.dupe(u8, "") },
                },
                .ctrl_in_username_lf => .{
                    .secret = .{
                        .basic = .{
                            .username = try alloc.dupe(u8, "alice\nbob"),
                            .secret = try alloc.dupe(u8, "valid-secret"),
                        },
                    },
                },
                .ctrl_in_username_del => .{
                    .secret = .{
                        .basic = .{
                            .username = try alloc.dupe(u8, "alice\x7f"),
                            .secret = try alloc.dupe(u8, "valid-secret"),
                        },
                    },
                },
                .ctrl_in_account => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                    .account = try alloc.dupe(u8, "bad\taccount"),
                },
                .empty_account => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                    .account = try alloc.dupe(u8, ""),
                },
                .ctrl_in_audience => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                    .audience = try alloc.dupe(u8, "https://api.example.com\r"),
                },
                .empty_audience => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                    .audience = try alloc.dupe(u8, ""),
                },
                .ctrl_in_scope => blk: {
                    const scopes = try alloc.alloc([]u8, 1);
                    scopes[0] = try alloc.dupe(u8, "read:packages\x1b");
                    break :blk .{
                        .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                        .scopes = scopes,
                    };
                },
                .empty_scope => blk: {
                    const scopes = try alloc.alloc([]u8, 1);
                    scopes[0] = try alloc.dupe(u8, "");
                    break :blk .{
                        .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                        .scopes = scopes,
                    };
                },
                .nul_in_basic_secret => .{
                    .secret = .{
                        .basic = .{
                            .username = try alloc.dupe(u8, "alice"),
                            .secret = try alloc.dupe(u8, "sec\x00ret"),
                        },
                    },
                },
                .nul_in_bearer_token => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok\x00en") },
                },
                .nul_in_identity_token => .{
                    .secret = .{ .identity_token = try alloc.dupe(u8, "id\x00tok") },
                },
                .until_expiration_without_expires_at => .{
                    .secret = .{ .bearer_token = try alloc.dupe(u8, "tok") },
                    .cache_policy = .until_expiration,
                    .expires_at = null,
                },
            };
        }
    };

    const BadProvider = struct {
        kind: InvalidFactory,

        fn get(ctx: ?*anyopaque, alloc: Allocator, _: Request) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.kind.build(alloc);
        }

        fn login(ctx: ?*anyopaque, alloc: Allocator, _: LoginInput) ProviderError!CredentialResult {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.kind.build(alloc);
        }
    };

    for (std.enums.values(InvalidFactory)) |variant| {
        const direct = try variant.build(gpa);
        defer direct.deinit(gpa);
        try testing.expectError(error.InvalidInput, direct.validate());

        var bad: BadProvider = .{ .kind = variant };
        const provider: Provider = .{
            .name = "bad-provider",
            .ctx = &bad,
            .getFn = BadProvider.get,
            .loginFn = BadProvider.login,
        };

        try testing.expectError(error.InvalidInput, provider.executeGet(gpa, .{ .target = target }));
        try testing.expectError(
            error.InvalidInput,
            provider.executeLogin(gpa, .{ .request = .{ .target = target, .operation = .login } }),
        );
        // Also rejected as seeded LoginInput.credential before invoking loginFn.
        try testing.expectError(
            error.InvalidInput,
            provider.executeLogin(gpa, .{
                .request = .{ .target = target, .operation = .login },
                .credential = &direct,
            }),
        );
    }

    // Request-side control chars / empty strings in account, audience, scopes also fail with InvalidInput.
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .account = "" }).validate(),
    );
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .account = "bad\nuser" }).validate(),
    );
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .audience = "" }).validate(),
    );
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .audience = "aud\x00" }).validate(),
    );
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .scopes = &.{""} }).validate(),
    );
    try testing.expectError(
        error.InvalidInput,
        (Request{ .target = target, .scopes = &.{"repo\r"} }).validate(),
    );

    // 4c. Metadata honesty: null expires_at / audience / scopes and false renewal capability
    // are never invented, and scopes distinguishes &.{"read:packages"} vs &.{} vs null.
    {
        // Case 1: scopes = null, expires_at = null, audience = null, supports_noninteractive_renewal = false
        const unknown_meta: CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "opaque-pat") },
            .account = null,
            .expires_at = null,
            .cache_policy = .eternal,
            .audience = null,
            .scopes = null,
            .supports_noninteractive_renewal = false,
        };
        defer unknown_meta.deinit(gpa);

        var echo_unknown: EchoProvider = .{ .template = &unknown_meta };
        const p_unknown: Provider = .{
            .name = "unknown-meta",
            .ctx = &echo_unknown,
            .getFn = EchoProvider.get,
            .loginFn = EchoProvider.login,
        };
        const chain_unknown: ProviderChain = .{ .providers = &.{p_unknown} };

        const got_unknown = try chain_unknown.get(gpa, .{ .target = target });
        defer got_unknown.deinit(gpa);
        try testing.expectEqual(@as(?[]u8, null), got_unknown.account);
        try testing.expectEqual(@as(?i64, null), got_unknown.expires_at);
        try testing.expectEqual(@as(?[]u8, null), got_unknown.audience);
        try testing.expectEqual(@as(?[][]u8, null), got_unknown.scopes);
        try testing.expect(!got_unknown.supports_noninteractive_renewal);
        try testing.expectEqual(CachePolicy.eternal, got_unknown.cache_policy);

        // Case 2: explicit empty scope slice (&.{}) remains non-null with len == 0
        const empty_scopes_slice = try gpa.alloc([]u8, 0);
        const explicit_empty_scopes: CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "zero-scope-token") },
            .scopes = empty_scopes_slice,
        };
        defer explicit_empty_scopes.deinit(gpa);

        var echo_empty: EchoProvider = .{ .template = &explicit_empty_scopes };
        const p_empty: Provider = .{
            .name = "empty-scopes",
            .ctx = &echo_empty,
            .getFn = EchoProvider.get,
            .loginFn = EchoProvider.login,
        };
        const chain_empty: ProviderChain = .{ .providers = &.{p_empty} };

        const got_empty = try chain_empty.get(gpa, .{ .target = target });
        defer got_empty.deinit(gpa);
        try testing.expect(got_empty.scopes != null);
        try testing.expectEqual(@as(usize, 0), got_empty.scopes.?.len);

        const login_empty = try chain_empty.login(gpa, .{
            .request = .{ .target = target, .operation = .login },
        });
        defer login_empty.deinit(gpa);
        try testing.expect(login_empty.scopes != null);
        try testing.expectEqual(@as(usize, 0), login_empty.scopes.?.len);

        // Case 3: explicit populated scope slice (&.{"read:packages"}) remains non-null with exact item
        const one_scope_slice = try gpa.alloc([]u8, 1);
        one_scope_slice[0] = try gpa.dupe(u8, "read:packages");
        const populated_scopes: CredentialResult = .{
            .secret = .{ .bearer_token = try gpa.dupe(u8, "scoped-token") },
            .scopes = one_scope_slice,
        };
        defer populated_scopes.deinit(gpa);

        var echo_pop: EchoProvider = .{ .template = &populated_scopes };
        const p_pop: Provider = .{
            .name = "populated-scopes",
            .ctx = &echo_pop,
            .getFn = EchoProvider.get,
            .loginFn = EchoProvider.login,
        };
        const chain_pop: ProviderChain = .{ .providers = &.{p_pop} };

        const got_pop = try chain_pop.get(gpa, .{ .target = target });
        defer got_pop.deinit(gpa);
        try testing.expect(got_pop.scopes != null);
        try testing.expectEqual(@as(usize, 1), got_pop.scopes.?.len);
        try testing.expectEqualStrings("read:packages", got_pop.scopes.?[0]);
    }
}

// ---------------------------------------------------------------------------
// 5. Target Normalization & Namespace Key Matrix
// ---------------------------------------------------------------------------

test "conformance matrix: Target normalization, port/scheme non-equivalence, IPv6, and serviceKeyAlloc" {
    const gpa = testing.allocator;

    // 5a. Equivalence of HTTPS://Registry.Example.COM:5000/ and https://registry.example.com:5000.
    {
        const upper_slash = try Target.parseAlloc(gpa, "HTTPS://Registry.Example.COM:5000/", .{});
        defer upper_slash.deinit(gpa);
        const canonical = try Target.parseAlloc(gpa, "https://registry.example.com:5000", .{});
        defer canonical.deinit(gpa);

        try testing.expect(upper_slash.eql(canonical));
        try testing.expect(canonical.eql(upper_slash));
        try testing.expectEqualStrings("https", upper_slash.scheme);
        try testing.expectEqualStrings("registry.example.com", upper_slash.host);
        try testing.expectEqual(@as(?u16, 5000), upper_slash.port);

        const uri_a = try upper_slash.formatUriAlloc(gpa);
        defer gpa.free(uri_a);
        const uri_b = try canonical.formatUriAlloc(gpa);
        defer gpa.free(uri_b);
        try testing.expectEqualStrings("https://registry.example.com:5000", uri_a);
        try testing.expectEqualStrings(uri_a, uri_b);

        const key_scheme_a = try upper_slash.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(key_scheme_a);
        const key_scheme_b = try canonical.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(key_scheme_b);
        try testing.expectEqualStrings(
            "credential-provider://https/registry.example.com:5000",
            key_scheme_a,
        );
        try testing.expectEqualStrings(key_scheme_a, key_scheme_b);

        const key_noscheme_a = try upper_slash.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_noscheme_a);
        const key_noscheme_b = try canonical.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_noscheme_b);
        try testing.expectEqualStrings(
            "container-registry://registry.example.com:5000",
            key_noscheme_a,
        );
        try testing.expectEqualStrings(key_noscheme_a, key_noscheme_b);
    }

    // 5b. Non-equivalence of https://registry.example.com, https://registry.example.com:443,
    // https://registry.example.com:5000, and http://registry.example.com.
    {
        const raw_distinct = [_][]const u8{
            "https://registry.example.com",
            "https://registry.example.com:443",
            "https://registry.example.com:5000",
            "http://registry.example.com",
        };

        var parsed: [raw_distinct.len]Target = undefined;
        var parsed_count: usize = 0;
        defer for (parsed[0..parsed_count]) |*t| t.deinit(gpa);

        for (raw_distinct, 0..) |raw, idx| {
            parsed[idx] = try Target.parseAlloc(gpa, raw, .{});
            parsed_count += 1;
        }

        for (parsed, 0..) |lhs, i| {
            const lhs_uri = try lhs.formatUriAlloc(gpa);
            defer gpa.free(lhs_uri);
            const lhs_scheme_key = try lhs.serviceKeyAlloc(gpa, "credential-provider://", true);
            defer gpa.free(lhs_scheme_key);

            for (parsed, 0..) |rhs, j| {
                const rhs_uri = try rhs.formatUriAlloc(gpa);
                defer gpa.free(rhs_uri);
                const rhs_scheme_key = try rhs.serviceKeyAlloc(gpa, "credential-provider://", true);
                defer gpa.free(rhs_scheme_key);

                if (i == j) {
                    try testing.expect(lhs.eql(rhs));
                    try testing.expectEqualStrings(lhs_uri, rhs_uri);
                    try testing.expectEqualStrings(lhs_scheme_key, rhs_scheme_key);
                } else {
                    try testing.expect(!lhs.eql(rhs));
                    try testing.expect(!std.mem.eql(u8, lhs_uri, rhs_uri));
                    try testing.expect(!std.mem.eql(u8, lhs_scheme_key, rhs_scheme_key));
                }
            }
        }

        // Authority-only keys (include_scheme = false) must also remain distinct across ports
        // (null vs :443 vs :5000).
        const key_default = try parsed[0].serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_default);
        const key_443 = try parsed[1].serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_443);
        const key_5000 = try parsed[2].serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_5000);

        try testing.expectEqualStrings("container-registry://registry.example.com", key_default);
        try testing.expectEqualStrings("container-registry://registry.example.com:443", key_443);
        try testing.expectEqualStrings("container-registry://registry.example.com:5000", key_5000);
        try testing.expect(!std.mem.eql(u8, key_default, key_443));
        try testing.expect(!std.mem.eql(u8, key_default, key_5000));
        try testing.expect(!std.mem.eql(u8, key_443, key_5000));
    }

    // 5c. Bracketed IPv6 (https://[2001:DB8::1]:5000) normalization and serviceKeyAlloc formatting
    // for both include_scheme = true ("credential-provider://") and include_scheme = false
    // ("container-registry://").
    {
        const ipv6 = try Target.parseAlloc(gpa, "https://[2001:DB8::1]:5000", .{});
        defer ipv6.deinit(gpa);
        const ipv6_slash = try Target.parseAlloc(gpa, "HTTPS://[2001:db8::1]:5000/", .{});
        defer ipv6_slash.deinit(gpa);

        try testing.expect(ipv6.eql(ipv6_slash));
        try testing.expectEqualStrings("https", ipv6.scheme);
        try testing.expectEqualStrings("[2001:db8::1]", ipv6.host);
        try testing.expectEqual(@as(?u16, 5000), ipv6.port);

        const uri = try ipv6.formatUriAlloc(gpa);
        defer gpa.free(uri);
        try testing.expectEqualStrings("https://[2001:db8::1]:5000", uri);

        const auth = try ipv6.authorityAlloc(gpa);
        defer gpa.free(auth);
        try testing.expectEqualStrings("[2001:db8::1]:5000", auth);

        const key_with_scheme = try ipv6.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(key_with_scheme);
        try testing.expectEqualStrings(
            "credential-provider://https/[2001:db8::1]:5000",
            key_with_scheme,
        );

        const key_without_scheme = try ipv6.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(key_without_scheme);
        try testing.expectEqualStrings(
            "container-registry://[2001:db8::1]:5000",
            key_without_scheme,
        );

        // Portless bracketed IPv6 is distinct from :5000 and formats cleanly in both modes.
        const ipv6_no_port = try Target.parseAlloc(gpa, "https://[2001:DB8::1]", .{});
        defer ipv6_no_port.deinit(gpa);
        try testing.expect(!ipv6.eql(ipv6_no_port));

        const no_port_scheme = try ipv6_no_port.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(no_port_scheme);
        try testing.expectEqualStrings("credential-provider://https/[2001:db8::1]", no_port_scheme);

        const no_port_bare = try ipv6_no_port.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(no_port_bare);
        try testing.expectEqualStrings("container-registry://[2001:db8::1]", no_port_bare);

        // RFC 5952 canonicalization: uncompressed uppercase IPv6 equals compressed lowercase IPv6
        // and yields identical serviceKeyAlloc keys.
        const ipv6_full = try Target.parseAlloc(
            gpa,
            "https://[2001:0DB8:0000:0000:0000:0000:0000:0001]:5000",
            .{},
        );
        defer ipv6_full.deinit(gpa);
        const ipv6_canon = try Target.parseAlloc(gpa, "https://[2001:db8::1]:5000", .{});
        defer ipv6_canon.deinit(gpa);

        try testing.expect(ipv6_full.eql(ipv6_canon));

        const full_scheme_key = try ipv6_full.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(full_scheme_key);
        const canon_scheme_key = try ipv6_canon.serviceKeyAlloc(gpa, "credential-provider://", true);
        defer gpa.free(canon_scheme_key);
        try testing.expectEqualStrings(canon_scheme_key, full_scheme_key);

        const full_reg_key = try ipv6_full.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(full_reg_key);
        const canon_reg_key = try ipv6_canon.serviceKeyAlloc(gpa, "container-registry://", false);
        defer gpa.free(canon_reg_key);
        try testing.expectEqualStrings(canon_reg_key, full_reg_key);

        // Malformed IPv6 literals are strictly rejected with error.InvalidInput.
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://[1:2]:5000", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://[2001:db8::1::2]", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://[:::1]", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://[2001:db800::1]", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://[1:2:3:4:5:6:7:8:9]", .{}));

        // RFC 1035 label/host length bounds and non-canonical/overflowing IPv4 forms are rejected.
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://192.0.2.256", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://0177.0.0.1", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://127.1", .{}));
        try testing.expectError(error.InvalidInput, Target.parseAlloc(gpa, "https://2130706433", .{}));
        const label_63 = &@as([63]u8, @splat('a'));
        const label_64 = &@as([64]u8, @splat('a'));
        const tail_62 = &@as([62]u8, @splat('b'));
        const tail_61 = &@as([61]u8, @splat('b'));
        try testing.expectError(
            error.InvalidInput,
            Target.parseAlloc(gpa, "https://" ++ label_64 ++ ".example.com", .{}),
        );
        try testing.expectError(
            error.InvalidInput,
            Target.parseAlloc(gpa, "https://" ++ label_63 ++ "." ++ label_63 ++ "." ++ label_63 ++ "." ++ tail_62, .{}),
        );

        // Exact RFC 1035 boundary (63-byte label, 253-byte host) and canonical IPv4 succeed.
        var max_valid = try Target.parseAlloc(
            gpa,
            "https://" ++ label_63 ++ "." ++ label_63 ++ "." ++ label_63 ++ "." ++ tail_61,
            .{},
        );
        defer max_valid.deinit(gpa);
        try testing.expectEqual(@as(usize, 253), max_valid.host.len);

        var valid_v4 = try Target.parseAlloc(gpa, "https://192.0.2.255:5000", .{});
        defer valid_v4.deinit(gpa);
        try testing.expectEqualStrings("192.0.2.255", valid_v4.host);
    }
}
