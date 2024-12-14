using System.Diagnostics;
using System.Reflection;
using System.Windows;


namespace UPRO.View
{
    /// <summary>
    /// Popup.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class PopupWindow : Window
    {
        public PopupWindow()
        {
            InitializeComponent();
            SetProductVersion();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void SetProductVersion()
        {
            // 현재 실행 중인 파일의 경로 가져오기
            string filePath = Assembly.GetExecutingAssembly().Location;

            // 파일 버전 정보 가져오기
            var fileVersionInfo = FileVersionInfo.GetVersionInfo(filePath);

            // Product Version 읽기
            string productVersion = fileVersionInfo.ProductVersion;

            // 현재 어셈블리의 버전 가져오기
            TxbVersion.Text = $"Product version: {productVersion}";
        }
    }
}
