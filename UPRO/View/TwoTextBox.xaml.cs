using System.Windows;


namespace UPRO.View
{
    /// <summary>
    /// TwoTextBox.xaml에 대한 상호 작용 논리
    /// </summary>
    public partial class TwoTextBox : Window
    {
        public string Result1 { get; private set; }
        public string Result2 { get; private set; }

        public TwoTextBox(string title, string message, string target1, string target2, string val1, string val2)
        {
            InitializeComponent();
            TxbTitle.Text = title;
            TxbMessgae.Text = message;
            TxbTarget1.Text = target1;
            TxbTarget2.Text = target2;
            TxtInput1.Text = val1;
            TxtInput2.Text = val2;
            this.Loaded += (s, e) =>
            {
                // TextBox에 포커스 설정 및 텍스트 선택
                TxtInput1.Focus();
                TxtInput1.SelectAll();
            };
        }

        private void CloseWindowButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }

        private void BtnOK_Click(object sender, RoutedEventArgs e)
        {
            Result1 = TxtInput1.Text;
            Result2 = TxtInput2.Text;
            this.DialogResult = true;
        }

        private void BtnClose_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }
    }
}
