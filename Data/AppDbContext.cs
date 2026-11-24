using Microsoft.EntityFrameworkCore;

namespace PasskeyAccountDemo.Data;

/// <summary>使用者帳號（帳號 + 密碼雜湊）</summary>
public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
    /// <summary>ASP.NET Core PasswordHasher 產生的雜湊（PBKDF2），絕不存明碼</summary>
    public string PasswordHash { get; set; } = "";
    /// <summary>WebAuthn user handle：隨機 32 bytes，不含個資</summary>
    public byte[] UserHandle { get; set; } = Array.Empty<byte>();
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public List<PasskeyCredential> Passkeys { get; set; } = new();
}

/// <summary>綁定到帳號的生物識別憑證（一個帳號可綁多台裝置）</summary>
public class PasskeyCredential
{
    public int Id { get; set; }
    public byte[] CredentialId { get; set; } = Array.Empty<byte>();
    /// <summary>COSE 格式公鑰。私鑰與指紋/臉部資料都留在使用者裝置上</summary>
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    /// <summary>簽章計數器，用來偵測被複製的驗證器</summary>
    public uint SignCount { get; set; }
    public string? DeviceName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAt { get; set; }

    public int UserId { get; set; }
    public User User { get; set; } = null!;
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<PasskeyCredential> Passkeys => Set<PasskeyCredential>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(u => u.Username).IsUnique();
            e.HasIndex(u => u.UserHandle).IsUnique();
            e.Property(u => u.Username).HasMaxLength(64).IsRequired();
            e.Property(u => u.UserHandle).HasMaxLength(64).IsRequired();
        });

        b.Entity<PasskeyCredential>(e =>
        {
            e.HasIndex(c => c.CredentialId).IsUnique();
            e.Property(c => c.CredentialId).HasMaxLength(1024).IsRequired();
            e.Property(c => c.PublicKey).IsRequired();
            e.Property(c => c.DeviceName).HasMaxLength(100);
            e.HasOne(c => c.User)
             .WithMany(u => u.Passkeys)
             .HasForeignKey(c => c.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
