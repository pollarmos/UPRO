using System.Windows;


namespace UPRO.View
{
    /// <summary>
    /// ErrorWindow.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class ErrorWindow : Window
    {
        public ErrorWindow(string Title, string message)
        {
            InitializeComponent();
            TxbTitle.Text = Title;
            TxbMessgae.Text = message;
        }

        private void CloseWindowButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}
