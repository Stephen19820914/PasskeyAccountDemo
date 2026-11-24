-- 參考用：SQL Server 版資料表（範例預設用 SQLite，啟動時由 EF Core 自動建立）

CREATE TABLE Users (
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    Username      NVARCHAR(64)   NOT NULL,
    PasswordHash  NVARCHAR(MAX)  NOT NULL,   -- PBKDF2 雜湊，不存明碼
    UserHandle    VARBINARY(64)  NOT NULL,   -- WebAuthn user.id（隨機 32 bytes）
    CreatedAt     DATETIME2      NOT NULL,
    CONSTRAINT UX_Users_Username   UNIQUE (Username),
    CONSTRAINT UX_Users_UserHandle UNIQUE (UserHandle)
);

CREATE TABLE Passkeys (
    Id            INT IDENTITY(1,1) PRIMARY KEY,
    UserId        INT            NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
    CredentialId  VARBINARY(1024) NOT NULL,
    PublicKey     VARBINARY(MAX) NOT NULL,   -- 只存公鑰；指紋/臉部資料不會傳到伺服器
    SignCount     BIGINT         NOT NULL,
    DeviceName    NVARCHAR(100)  NULL,
    CreatedAt     DATETIME2      NOT NULL,
    LastUsedAt    DATETIME2      NULL,
    CONSTRAINT UX_Passkeys_CredentialId UNIQUE (CredentialId)
);

CREATE INDEX IX_Passkeys_UserId ON Passkeys(UserId);
