using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Xml.Linq;

namespace UPRO.Util
{
    public class UpdateManager
    {
        private const string VersionUrl = @"http://119.207.163.69/version.json";
        private const string TempFileName = "UPRO_New.exe";

        public static async Task<bool> CheckForUpdates()
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // 서버에서 최신 버전 정보 가져오기
                    string json = await client.GetStringAsync(VersionUrl);

                    // JSON 데이터 파싱
                    var serializer = new JavaScriptSerializer();
                    dynamic versionInfo = serializer.Deserialize<dynamic>(json);

                    string latestVersion = versionInfo["version"];
                    string downloadUrl = versionInfo["downloadUrl"];

                    // 현재 실행 중인 앱의 버전 확인
                    string filePath = Assembly.GetExecutingAssembly().Location;
                    string currentVersion = FileVersionInfo.GetVersionInfo(filePath).FileVersion;

                    if (new Version(latestVersion) > new Version(currentVersion))
                    {
                        MessageBox.Show($"A new version ({latestVersion}) is available. Current version: {currentVersion}");
                        return await DownloadUpdate(downloadUrl);
                    }
                    else
                    {
                        MessageBox.Show("This is the latest version.");
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error checking for updates: {ex.Message}");
            }

            return false;
        }

        private static async Task<bool> DownloadUpdate(string url)
        {
            try
            {
                using (HttpClient client = new HttpClient())
                {
                    byte[] fileData = await client.GetByteArrayAsync(url);

                    // 새 파일 다운로드
                    string tempFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, TempFileName);

                    // 동기 방식으로 파일 쓰기
                    File.WriteAllBytes(tempFilePath, fileData);

                    MessageBox.Show("The update file has been downloaded");
                    return true;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error occurred while downloading the update file: {ex.Message}");
                return false;
            }
        }

        public static void ApplyUpdateAndRestart()
        {
            try
            {
                string currentFilePath = Assembly.GetExecutingAssembly().Location;
                string tempFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, TempFileName);

                if (File.Exists(tempFilePath))
                {
                    // 기존 실행 파일 백업 및 교체
                    string backupFilePath = currentFilePath + ".bak";
                    File.Move(currentFilePath, backupFilePath);  // 기존 파일 백업
                    File.Move(tempFilePath, currentFilePath);   // 새 파일 교체

                    MessageBox.Show("Update completed. Restarting the application...");

                    // 새 파일 실행 및 앱 종료
                    System.Diagnostics.Process.Start(currentFilePath);
                    Environment.Exit(0);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error occurred while applying the update: {ex.Message}");
            }
        }
    }
}
