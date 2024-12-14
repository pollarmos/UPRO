using System.Windows;


namespace UPRO.View
{
    /// <summary>
    /// InformWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class InformWindow : Window
    {
        public InformWindow(string message)
        {
            InitializeComponent();
            TxbMessage.Text = message;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
