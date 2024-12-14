using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Data;

namespace UPRO.Util
{
    public class ImageConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is int intValue)
            {
                try
                {
                    // OnDrawingImage와 OffDrawingImage를 Application 리소스에서 가져오기
                    return intValue == 0
                        ? Application.Current.FindResource("OffDrawingImage")
                        : Application.Current.FindResource("OnDrawingImage");
                }
                catch (ResourceReferenceKeyNotFoundException ex)
                {
                    Debug.WriteLine($"Resource not found: {ex.Message}");
                    return null;
                }
            }
            return null;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
