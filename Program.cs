using System;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace remoteRun
{
    class Program
    {
        static void Main(string[] args)
        {
            // DPAPI 암호화 값 생성 (최초 1회):
            // remoteRun.exe --encrypt-conn "server=...;uid=...;pwd=...;database=..."
            if (args.Length >= 2 && args[0] == "--encrypt-conn")
            {
                string encrypted = DpapiHelper.ProtectForConfig(args[1]);
                Console.WriteLine("App.config connectionString에 아래 값을 넣으세요:");
                Console.WriteLine(encrypted);
                return;
            }

            string user = GetDecryptedAdminPassword("AD_USER");
            string password = GetDecryptedAdminPassword("AD_PASS");

            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(password))
            {
                Console.WriteLine("[종료] AD 계정 정보 조회 실패로 원격 실행을 중단합니다.");
                return;
            }

            fun_RemoteComputerEtcInfo(user, password, "152.149.148.91");
        }

        static string GetDecryptedAdminPassword(string encryptedUser)
        {
            try
            {
                using (SqlConnection conn = getConnectToMSSQL("ezResource"))
                {
                    conn.Open();

                    string query = "SELECT Username FROM MISPasswordAdmin WHERE id = @id AND useflag = 'Y'";
                    using (SqlCommand cmd = new SqlCommand(query, conn))
                    {
                        cmd.Parameters.AddWithValue("@id", encryptedUser);
                        string encryptedPassword = cmd.ExecuteScalar()?.ToString();

                        if (!string.IsNullOrEmpty(encryptedPassword))
                            return DecryptPassword(encryptedPassword);

                        Console.WriteLine($"[경고] DB에서 유효한 AD 관리자 정보를 찾을 수 없습니다. ({encryptedUser})");
                        return string.Empty;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[오류] DB 관리자 비밀번호 로드 및 복호화 중 오류 발생: {ex.Message}");
                return string.Empty;
            }
        }

        static string DecryptPassword(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            byte[] keyBytes = SecureConfig.GetAesKeyBytes();

            byte[] ivBytes = new byte[16];
            Array.Copy(keyBytes, ivBytes, 16);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.BlockSize = 128;
                aes.Key = keyBytes;
                aes.IV = ivBytes;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        byte[] cipherBytes = Convert.FromBase64String(cipherText);
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.FlushFinalBlock();
                    }
                    return Encoding.UTF8.GetString(ms.ToArray());
                }
            }
        }

        static string fun_RemoteComputerEtcInfo(string strUsername, string strPassword, string strIP)
        {
            string lsReturn = "";

            ConnectionOptions options = new ConnectionOptions
            {
                Username = strUsername,
                Password = strPassword,
                Impersonation = ImpersonationLevel.Impersonate,
                EnablePrivileges = true,
                Authentication = AuthenticationLevel.PacketPrivacy,
                Authority = "ntlmdomain:"
            };

            try
            {
                string wmiPath = string.Format(@"\\{0}\root\cimv2", strIP);
                ManagementScope ms = new ManagementScope(wmiPath, options);
                ms.Connect();

                ManagementPath path = new ManagementPath("Win32_Process");
                ManagementClass processClass = new ManagementClass(ms, path, null);

                string strProcess = @"C:\AD_BAT\RUN\ADVendorIDProcess.exe";
                object[] methodArgs = { strProcess, null, null, 0 };
                processClass.InvokeMethod("Create", methodArgs);
            }
            catch (Exception ex)
            {
                lsReturn = "ERROR";
                Console.Out.WriteLine(string.Format("Can't Connect to Server: {0}\n{1}", strIP, ex.ToString()));
                WriteTextLog("E", "Can't Connect to Server:" + strIP, ex.ToString());
            }

            return lsReturn;
        }

        protected static SqlConnection getConnectToMSSQL(string as_system)
        {
            return new SqlConnection(SecureConfig.GetConnectionString(as_system));
        }

        private static void WriteTextLog(string pGugn, string pMethod, string pMessage)
        {
            string lsToDay = string.Format("{0:yyyyMMdd}", DateTime.Now);
            string lsFileDay = "";

            try
            {
                string folderpath = "C:\\AD_BAT";
                if (string.IsNullOrEmpty(folderpath))
                    return;

                string filepath = folderpath + "\\LOG";
                if (!Directory.Exists(filepath))
                    Directory.CreateDirectory(filepath);

                filepath += "\\ADVendorIDProcess_" + string.Format("{0:dd}", DateTime.Now) + ".txt";

                if (File.Exists(filepath))
                {
                    var info = new FileInfo(filepath);
                    lsFileDay = string.Format("{0:yyyyMMdd}", info.LastWriteTime);
                    if (lsFileDay != lsToDay)
                        File.Delete(filepath);
                }

                using (StreamWriter output = new StreamWriter(filepath, true, Encoding.Default))
                {
                    output.WriteLine("[" + DateTime.UtcNow.AddHours(9).ToLongTimeString() + "] " + pMethod.Trim());
                    output.WriteLine(pMessage);
                    output.WriteLine();
                }

                using (SqlConnection conn = getConnectToMSSQL("DSOM"))
                {
                    conn.Open();
                    using (SqlCommand comd = new SqlCommand("SP_AD_LOG_SAVE", conn))
                    {
                        comd.CommandType = CommandType.StoredProcedure;
                        comd.Parameters.Add("@vGubn", SqlDbType.NChar, 1);
                        comd.Parameters.Add("@vEventPos", SqlDbType.VarChar, 50);
                        comd.Parameters.Add("@vContents", SqlDbType.VarChar, 1000);
                        comd.Parameters["@vGubn"].Value = pGugn;
                        comd.Parameters["@vEventPos"].Value = pMethod;
                        comd.Parameters["@vContents"].Value = pMessage;
                        comd.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception)
            {
                // 로그 실패는 원격 실행 흐름을 중단하지 않음
            }
        }
    }
}
