namespace Common.Security.Models
{
    using System;
    using System.ComponentModel;

    public class ApplicationUserInfo : INotifyPropertyChanging, INotifyPropertyChanged
    {
        public virtual Guid ID { get; set; }

        public virtual Guid? UserID { get; set; }

        private string? department;
        public virtual string? Department
        {
            get => department;
            set { OnPropertyChanging(nameof(Department)); department = value; OnPropertyChanged(nameof(Department)); }
        }

        private string? displayName;
        public virtual string? DisplayName
        {
            get => displayName;
            set { OnPropertyChanging(nameof(DisplayName)); displayName = value; OnPropertyChanged(nameof(DisplayName)); }
        }

        public virtual long UserAccountControl { get; set; }

        private string? mail;
        public virtual string? Mail
        {
            get => mail;
            set { OnPropertyChanging(nameof(Mail)); mail = value; OnPropertyChanged(nameof(Mail)); }
        }

        private string? manager;
        public virtual string? Manager
        {
            get => manager;
            set { OnPropertyChanging(nameof(Manager)); manager = value; OnPropertyChanged(nameof(Manager)); }
        }

        private string? mobile;
        public virtual string? Mobile
        {
            get => mobile;
            set { OnPropertyChanging(nameof(Mobile)); mobile = value; OnPropertyChanged(nameof(Mobile)); }
        }

        private string? otherMobile;
        public virtual string? OtherMobile
        {
            get => otherMobile;
            set { OnPropertyChanging(nameof(OtherMobile)); otherMobile = value; OnPropertyChanged(nameof(OtherMobile)); }
        }

        private string? telephoneNumber;
        public virtual string? TelephoneNumber
        {
            get => telephoneNumber;
            set { OnPropertyChanging(nameof(TelephoneNumber)); telephoneNumber = value; OnPropertyChanged(nameof(TelephoneNumber)); }
        }

        private string? otherTelephoneNumber;
        public virtual string? OtherTelephoneNumber
        {
            get => otherTelephoneNumber;
            set { OnPropertyChanging(nameof(OtherTelephoneNumber)); otherTelephoneNumber = value; OnPropertyChanged(nameof(OtherTelephoneNumber)); }
        }

        private string? title;
        public virtual string? Title
        {
            get => title;
            set { OnPropertyChanging(nameof(Title)); title = value; OnPropertyChanged(nameof(Title)); }
        }

        private byte[]? photo;
        public virtual byte[]? Photo
        {
            get => photo;
            set { OnPropertyChanging(nameof(Photo)); photo = value; OnPropertyChanged(nameof(Photo)); }
        }

        private DateTime lastSync;
        public virtual DateTime LastSync
        {
            get => lastSync;
            set { OnPropertyChanging(nameof(LastSync)); lastSync = value; OnPropertyChanged(nameof(LastSync)); }
        }

        public virtual ApplicationUser? User { get; set; }

        public event PropertyChangingEventHandler? PropertyChanging;
        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanging(string propertyName) => PropertyChanging?.Invoke(this, new PropertyChangingEventArgs(propertyName));
        protected void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}