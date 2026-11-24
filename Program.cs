using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PasskeyAccountDemo.Data;

var builder = WebApplication.CreateBuilder(args);

// ---------------- 服務設定 ----------------
builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default")));
// SQL Server：o.UseSqlServer(builder.Configuration.GetConnectionString("Default"))

builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.IdleTimeout = TimeSpan.FromMinutes(5);
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
    });
builder.Services.AddAuthorization();

builder.Services.AddFido2(o =>
{
    o.ServerDomain = builder.Configuration["Fido2:ServerDomain"] ?? "localhost";
    o.ServerName = "Passkey Account Demo";
    o.Origins = new HashSet<string>(builder.Configuration.GetSection("Fido2:Origins").Get<string[]>()
                                    ?? new[] { "https://localhost:5001" });
    o.TimestampDriftTolerance = 300000;
});

var app = builder.Build();

// 示範用：啟動時自動建表。正式環境請改用 EF Core Migrations
using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.EnsureCreated();

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

const string SignupKey = "signup.pending";
const string AttestKey = "fido2.attestationOptions";
const string AssertKey = "fido2.assertionOptions";

// =====================================================================
// A. 註冊：帳號密碼 + 生物識別，一次寫入資料庫
// =====================================================================

// A-1. 檢查帳號密碼 → 雜湊密碼暫存在 Session → 回傳 WebAuthn 建立選項
app.MapPost("/api/signup/options", async (SignupRequest req, AppDbContext db,
    IPasswordHasher<User> hasher, IFido2 fido2, HttpContext ctx) =>
{
    var username = req.Username?.Trim() ?? "";
    if (username.Length is < 3 or > 64)
        return Error("帳號長度需為 3～64 字元");
    if ((req.Password ?? "").Length < 8)
        return Error("密碼至少 8 個字元");
    if (await db.Users.AnyAsync(u => u.Username == username))
        return Error("此帳號已被使用");

    var pending = new PendingSignup(
        username,
        hasher.HashPassword(null!, req.Password!),   // 先雜湊，Session 裡不留明碼
        RandomNumberGenerator.GetBytes(32),
        req.DeviceName);

    // Fido2 4.x：參數改成傳一個 RequestNewCredentialParams 物件
    var options = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = new Fido2User { Id = pending.UserHandle, Name = username, DisplayName = username },
        ExcludeCredentials = Array.Empty<PublicKeyCredentialDescriptor>(),
        AuthenticatorSelection = PlatformBiometricSelection(),
        AttestationPreference = AttestationConveyancePreference.None,
        Extensions = new AuthenticationExtensionsClientInputs { CredProps = true }
    });

    ctx.Session.SetString(SignupKey, JsonSerializer.Serialize(pending));
    ctx.Session.SetString(AttestKey, options.ToJson());
    return Results.Content(options.ToJson(), "application/json");
});

// A-2. 驗證生物識別 → 帳號 + Passkey 在同一個交易中寫入
app.MapPost("/api/signup/verify", async (AuthenticatorAttestationRawResponse attestation,
    AppDbContext db, IFido2 fido2, HttpContext ctx, CancellationToken ct) =>
{
    var pendingJson = ctx.Session.GetString(SignupKey);
    var optionsJson = ctx.Session.GetString(AttestKey);
    ctx.Session.Remove(SignupKey);
    ctx.Session.Remove(AttestKey);
    if (pendingJson is null || optionsJson is null)
        return Error("註冊逾時，請重新填寫");

    var pending = JsonSerializer.Deserialize<PendingSignup>(pendingJson)!;
    var options = CredentialCreateOptions.FromJson(optionsJson);

    // Fido2 4.x：驗證失敗直接丟例外，成功回傳 RegisteredPublicKeyCredential
    RegisteredPublicKeyCredential success;
    try
    {
        success = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestation,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = async (args, token) =>
                !await db.Passkeys.AnyAsync(p => p.CredentialId == args.CredentialId, token)
        }, ct);
    }
    catch (Fido2VerificationException ex) { return Error("生物識別驗證失敗：" + ex.Message); }

    var user = new User
    {
        Username = pending.Username,
        PasswordHash = pending.PasswordHash,
        UserHandle = pending.UserHandle,
        Passkeys =
        {
            new PasskeyCredential
            {
                CredentialId = success.Id,
                PublicKey = success.PublicKey,
                SignCount = success.SignCount,
                DeviceName = pending.DeviceName
            }
        }
    };

    // User 與 PasskeyCredential 在同一次 SaveChanges → EF Core 自動包成一個交易
    db.Users.Add(user);
    try { await db.SaveChangesAsync(ct); }
    catch (DbUpdateException) { return Error("此帳號已被使用"); } // 兩人同時註冊同帳號

    await SignInAsync(ctx, user);
    return Results.Ok(new { ok = true, username = user.Username });
});

// =====================================================================
// B. 登入方式一：帳號 + 密碼
// =====================================================================
app.MapPost("/api/login/password", async (PasswordLoginRequest req, AppDbContext db,
    IPasswordHasher<User> hasher, HttpContext ctx) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == (req.Username ?? "").Trim());
    if (user is null ||
        hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password ?? "") == PasswordVerificationResult.Failed)
        return Error("帳號或密碼錯誤");

    await SignInAsync(ctx, user);
    return Results.Ok(new { ok = true, username = user.Username });
});

// =====================================================================
// C. 登入方式二：生物識別（Passkey，免輸入帳號）
// =====================================================================
app.MapPost("/api/login/passkey/options", (IFido2 fido2, HttpContext ctx) =>
{
    var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
    {
        AllowedCredentials = Array.Empty<PublicKeyCredentialDescriptor>(), // 空 = 讓瀏覽器列出本機 Passkey
        UserVerification = UserVerificationRequirement.Required
    });

    ctx.Session.SetString(AssertKey, options.ToJson());
    return Results.Content(options.ToJson(), "application/json");
});

app.MapPost("/api/login/passkey/verify", async (AuthenticatorAssertionRawResponse assertion,
    AppDbContext db, IFido2 fido2, HttpContext ctx, CancellationToken ct) =>
{
    var optionsJson = ctx.Session.GetString(AssertKey);
    ctx.Session.Remove(AssertKey);
    if (optionsJson is null) return Error("登入逾時，請重試");

    var cred = await db.Passkeys.Include(p => p.User)
        .FirstOrDefaultAsync(p => p.CredentialId == assertion.RawId, ct); // 4.x：Id 是字串，byte[] 用 RawId
    if (cred is null) return Error("此裝置的生物識別尚未綁定任何帳號");

    try
    {
        var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = assertion,
            OriginalOptions = AssertionOptions.FromJson(optionsJson),
            StoredPublicKey = cred.PublicKey,
            StoredSignatureCounter = cred.SignCount,
            IsUserHandleOwnerOfCredentialIdCallback = (args, _) =>
                Task.FromResult(args.UserHandle is null || args.UserHandle.SequenceEqual(cred.User.UserHandle))
        }, ct);

        cred.SignCount = result.SignCount;
        cred.LastUsedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
    }
    catch (Fido2VerificationException ex) { return Error("生物識別驗證失敗：" + ex.Message); }

    await SignInAsync(ctx, cred.User);
    return Results.Ok(new { ok = true, username = cred.User.Username });
});

// =====================================================================
// D. 已登入：在另一台裝置加綁生物識別
// =====================================================================
app.MapPost("/api/passkeys/options", async (AppDbContext db, IFido2 fido2, HttpContext ctx, ClaimsPrincipal me) =>
{
    var userId = UserId(me); // 先算出來；EF Core 的 LINQ 運算式裡不能呼叫區域函式
    var user = await db.Users.Include(u => u.Passkeys).FirstAsync(u => u.Id == userId);

    var options = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = new Fido2User { Id = user.UserHandle, Name = user.Username, DisplayName = user.Username },
        ExcludeCredentials = user.Passkeys.Select(p => new PublicKeyCredentialDescriptor(p.CredentialId)).ToList(),
        AuthenticatorSelection = PlatformBiometricSelection(),
        AttestationPreference = AttestationConveyancePreference.None,
        Extensions = new AuthenticationExtensionsClientInputs { CredProps = true }
    });

    ctx.Session.SetString(AttestKey, options.ToJson());
    return Results.Content(options.ToJson(), "application/json");
}).RequireAuthorization();

app.MapPost("/api/passkeys/verify", async ([FromQuery] string? device, AuthenticatorAttestationRawResponse attestation,
    AppDbContext db, IFido2 fido2, HttpContext ctx, ClaimsPrincipal me, CancellationToken ct) =>
{
    var optionsJson = ctx.Session.GetString(AttestKey);
    ctx.Session.Remove(AttestKey);
    if (optionsJson is null) return Error("逾時，請重試");

    try
    {
        var result = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = attestation,
            OriginalOptions = CredentialCreateOptions.FromJson(optionsJson),
            IsCredentialIdUniqueToUserCallback = async (args, token) =>
                !await db.Passkeys.AnyAsync(p => p.CredentialId == args.CredentialId, token)
        }, ct);

        db.Passkeys.Add(new PasskeyCredential
        {
            UserId = UserId(me),
            CredentialId = result.Id,
            PublicKey = result.PublicKey,
            SignCount = result.SignCount,
            DeviceName = device is { Length: > 100 } ? device[..100] : device
        });
        await db.SaveChangesAsync(ct);
        return Results.Ok(new { ok = true });
    }
    catch (Fido2VerificationException ex) { return Error(ex.Message); }
}).RequireAuthorization();

// =====================================================================
// E. 其他
// =====================================================================
app.MapGet("/api/me", async (AppDbContext db, ClaimsPrincipal me) =>
{
    var id = UserId(me);
    var user = await db.Users.Where(u => u.Id == id)
        .Select(u => new
        {
            u.Username,
            u.CreatedAt,
            Passkeys = u.Passkeys.Select(p => new { p.Id, p.DeviceName, p.CreatedAt, p.LastUsedAt })
        })
        .FirstOrDefaultAsync();
    return user is null ? Results.Unauthorized() : Results.Ok(user);
}).RequireAuthorization();

app.MapPost("/api/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Ok();
});

app.Run();

// ---------------- 輔助方法 ----------------
static IResult Error(string message) => Results.BadRequest(new { error = message });

static int UserId(ClaimsPrincipal p) => int.Parse(p.FindFirstValue(ClaimTypes.NameIdentifier)!);

static AuthenticatorSelection PlatformBiometricSelection() => new()
{
    AuthenticatorAttachment = AuthenticatorAttachment.Platform,       // 本機：Windows Hello / Touch ID / 手機指紋
    ResidentKey = ResidentKeyRequirement.Required,                    // Passkey，可免帳號登入
    UserVerification = UserVerificationRequirement.Required           // 必須通過生物識別或裝置 PIN
};

static Task SignInAsync(HttpContext ctx, User user)
{
    var identity = new ClaimsIdentity(new[]
    {
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new Claim(ClaimTypes.Name, user.Username)
    }, CookieAuthenticationDefaults.AuthenticationScheme);
    return ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
}

// ---------------- DTO ----------------
record SignupRequest(string? Username, string? Password, string? DeviceName);
record PasswordLoginRequest(string? Username, string? Password);
record PendingSignup(string Username, string PasswordHash, byte[] UserHandle, string? DeviceName);
