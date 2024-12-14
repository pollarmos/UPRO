using System.Windows;


namespace UPRO.View
{
    /// <summary>
    /// OneTextBox.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class OneTextBox : Window
    {
        public string Result { get; private set; }

        public OneTextBox(string title, string message, string val)
        {
            InitializeComponent();
            TxtInput.Text = val;
            TxbTitle.Text = title;
            TxbMessgae.Text = message;

            this.Loaded += (s, e) =>
            {
                // TextBox에 포커스 설정 및 텍스트 선택
                TxtInput.Focus();
                TxtInput.SelectAll();
            };
        }

        private void CloseWindowButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }

        private void BtnOK_Click(object sender, RoutedEventArgs e)
        {
            Result = TxtInput.Text;
            this.DialogResult = true;
        }
    }
}
