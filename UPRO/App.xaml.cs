using System.Windows;
using UPRO.Util;

namespace UPRO
{
    /// <summary>
    /// App.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class App : Application
    {
        protected override async void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // 업데이트 확인 및 다운로드
            bool updateDownloaded = await UpdateManager.CheckForUpdates();
            if (updateDownloaded)
            {
                UpdateManager.ApplyUpdateAndRestart();
                return; // 업데이트를 적용했으므로 기존 앱 실행 방지
            }

            // MainWindow 실행
            var upro = new UPRO.View.UPRO();
            upro.Show();
        }
    }
}
