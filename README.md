# PasskeyAccountDemo — 帳號密碼註冊時同步綁定生物識別

## 執行
```bash
dotnet dev-certs https --trust
dotnet run
```
用 Chrome 開 https://localhost:5001，資料庫檔 `app.db` 會自動建立。

## 註冊流程（帳號＋生物識別一起寫入 DB）
```
① POST /api/signup/options  {username, password}
     伺服器：檢查帳號、雜湊密碼 → 暫存 Session（尚未寫 DB）
② navigator.credentials.create()   ← Chrome 要求指紋/臉部/Windows Hello
③ POST /api/signup/verify   {attestation}
     伺服器：驗證生物識別 → Users + Passkeys 同一次 SaveChanges（同一交易）寫入
```
生物識別取消或失敗時，帳號不會被建立，不會留下沒有綁定的帳號。

## 登入
- 生物識別：免輸入帳號，Chrome 列出本機 Passkey
- 帳號密碼：在沒有生物識別的裝置上用

## 資料表
- `Users`：Username、PasswordHash、UserHandle
- `Passkeys`：CredentialId、PublicKey、SignCount、DeviceName（一個帳號可綁多台裝置）

SQL Server 版本見 `schema.sql`。要換成 SQL Server：
1. csproj 改用 `Microsoft.EntityFrameworkCore.SqlServer`
2. Program.cs 改 `UseSqlServer(...)`
3. 修改 `ConnectionStrings:Default`

## 上線前
- `EnsureCreated()` 改成 EF Core Migrations
- 改 `Fido2:ServerDomain` / `Fido2:Origins` 為正式網域
- 多台伺服器時，Session 改用 Redis 或 SQL 分散式快取
- 密碼登入加上失敗次數鎖定
