using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UPRO.Model
{
    public class Item : INotifyPropertyChanged
    {
        private int isToggled;
        public int IsToggled 
        {
            get => isToggled;
            set
            {
                isToggled = value;
                OnPropertyChanged(nameof(IsToggled));
            }
        }
        public int Id { get; set; }
        public int Group { get; set; }
        public bool Recommend { get; set; }
        public string Name { get; set; }
        public Func<bool> OnToggle { get; set; }
        public List<Patch> PatchList { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }

    public class Patch
    {
        public int Offset { get; set; }
        public string Hex { get; set; }
    }
}
