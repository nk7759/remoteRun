using System;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;

namespace remoteRun
{
    /// <summary>
    /// DB 연결 문자열·AES 키를 환경 변수 또는 App.config에서 안전하게 읽습니다.
    /// </summary>
    internal static class SecureConfig
    {
        private const string EncryptedPrefix = "encrypted:";

        /// <summary>
        /// 연결 문자열 조회 (우선순위: 환경 변수 → App.config → DPAPI 복호화)
        /// 환경 변수 이름 예: EZRESOURCE_CONN, DSOM_CONN
        /// </summary>
        public static string GetConnectionString(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("연결 이름이 비어 있습니다.", nameof(name));

            string envKey = $"{name.ToUpperInvariant()}_CONN";
            string fromEnv = Environment.GetEnvironmentVariable(envKey, EnvironmentVariableTarget.Machine)
                ?? Environment.GetEnvironmentVariable(envKey, EnvironmentVariableTarget.User)
                ?? Environment.GetEnvironmentVariable(envKey, EnvironmentVariableTarget.Process);

            if (!string.IsNullOrWhiteSpace(fromEnv))
                return fromEnv.Trim();

            ConnectionStringSettings setting = ConfigurationManager.ConnectionStrings[name];
            if (setting == null || string.IsNullOrWhiteSpace(setting.ConnectionString))
            {
                throw new InvalidOperationException(
                    $"'{name}' DB 연결 정보가 없습니다. " +
                    $"환경 변수 '{envKey}' 또는 App.config connectionStrings를 설정하세요.");
            }

            string connStr = setting.ConnectionString.Trim();
            if (connStr.StartsWith(EncryptedPrefix, StringComparison.OrdinalIgnoreCase))
            {
                string cipherBase64 = connStr.Substring(EncryptedPrefix.Length);
                return DpapiHelper.Unprotect(cipherBase64);
            }

            return connStr;
        }

        /// <summary>
        /// AES 복호화 키 조회 (환경 변수 REMOTERUN_AES_KEY 우선)
        /// </summary>
        public static byte[] GetAesKeyBytes()
        {
            const string envKey = "REMOTERUN_AES_KEY";
            string key = Environment.GetEnvironmentVariable(envKey, EnvironmentVariableTarget.Machine)
                ?? Environment.GetEnvironmentVariable(envKey, EnvironmentVariableTarget.User)
                ?? ConfigurationManager.AppSettings[envKey];

            if (string.IsNullOrWhiteSpace(key))
            {
                throw new InvalidOperationException(
                    $"AES 키가 설정되지 않았습니다. 환경 변수 '{envKey}' 또는 App.config appSettings를 설정하세요.");
            }

            byte[] keyBytes = new byte[32];
            byte[] secretKeyBytes = Encoding.UTF8.GetBytes(key.Trim());
            Array.Copy(secretKeyBytes, keyBytes, Math.Min(secretKeyBytes.Length, keyBytes.Length));
            return keyBytes;
        }
    }

    /// <summary>
    /// Windows DPAPI로 연결 문자열 암·복호화
    /// </summary>
    internal static class DpapiHelper
    {
        private const string EncryptedPrefix = "encrypted:";

        /// <summary>
        /// 평문 연결 문자열 → App.config에 넣을 "encrypted:..." 값 생성
        /// </summary>
        public static string ProtectForConfig(string plainText, DataProtectionScope scope = DataProtectionScope.LocalMachine)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] protectedBytes = ProtectedData.Protect(plainBytes, null, scope);
            return EncryptedPrefix + Convert.ToBase64String(protectedBytes);
        }

        public static string Unprotect(string cipherBase64, DataProtectionScope scope = DataProtectionScope.LocalMachine)
        {
            if (string.IsNullOrEmpty(cipherBase64))
                return string.Empty;

            byte[] protectedBytes = Convert.FromBase64String(cipherBase64);
            byte[] plainBytes = ProtectedData.Unprotect(protectedBytes, null, scope);
            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
