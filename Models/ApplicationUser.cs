namespace Common.Security.Models
{
    using System.ComponentModel;
    using System.Runtime.CompilerServices;

    public class ApplicationUser : INotifyPropertyChanging, INotifyPropertyChanged
    {
        private int accessFailedCount;
        private DateTime lockoutEnd;
        private bool isLockoutEnabled;
        private ApplicationUserInfo? userInfo;

        [Browsable(false)]
        public virtual int AccessFailedCount
        {
            get => accessFailedCount;
            set => SetProperty(ref accessFailedCount, value);
        }

        [Browsable(false)]
        public virtual DateTime LockoutEnd
        {
            get => lockoutEnd;
            set => SetProperty(ref lockoutEnd, value);
        }

        [Browsable(false)]
        public virtual bool IsLockoutEnabled
        {
            get => isLockoutEnabled;
            set => SetProperty(ref isLockoutEnabled, value);
        }

        [Browsable(false)]
        public virtual ApplicationUserInfo? UserInfo
        {
            get => userInfo;
            set => SetProperty(ref userInfo, value);
        }

        [Browsable(true)]
        public virtual string? DisplayName => UserInfo?.DisplayName;

        [Browsable(true)]
        public virtual string? Mail => UserInfo?.Mail;

        [Browsable(true)]
        public virtual string? Department => UserInfo?.Department;

        [Browsable(true)]
        public virtual string? Manager => UserInfo?.Manager;

        [Browsable(true)]
        public virtual string? Mobile => UserInfo?.Mobile;

        [Browsable(true)]
        public virtual string? OtherMobile => UserInfo?.OtherMobile;

        [Browsable(true)]
        public virtual string? TelephoneNumber => UserInfo?.TelephoneNumber;

        [Browsable(true)]
        public virtual string? OtherTelephoneNumber => UserInfo?.OtherTelephoneNumber;

        [Browsable(true)]
        public virtual string? Title => UserInfo?.Title;

        public virtual byte[]? Photo => UserInfo?.Photo;

        public event PropertyChangingEventHandler? PropertyChanging;
        public event PropertyChangedEventHandler? PropertyChanged;

        protected void SetProperty<T>(ref T field, T value, [CallerMemberName] string propertyName = Constants.StringConstants.EmptyString)
        {
            if (EqualityComparer<T>.Default.Equals(field, value))
                return;

            PropertyChanging?.Invoke(this, new PropertyChangingEventArgs(propertyName));
            field = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}