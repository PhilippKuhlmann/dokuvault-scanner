using System.Windows;
using System.Windows.Input;
using DokuVault.Scanner.Infrastructure;
using DokuVault.Scanner.ViewModels;

namespace DokuVault.Scanner.Views;

public partial class LoginWindow : Window
{
    private readonly LoginViewModel _vm;

    public LoginWindow(LoginViewModel vm)
    {
        InitializeComponent();
        DataContext = _vm = vm;
        ThemeManager.Attach(this);
        Loaded += (_, _) =>
        {
            if (string.IsNullOrEmpty(vm.Server))
                ServerBox.Focus();
            else if (string.IsNullOrEmpty(vm.Username))
                UserBox.Focus();
            else
                PasswordBox.Focus();
        };
    }

    private async void OnSignIn(object sender, RoutedEventArgs e)
    {
        if (_vm.IsBusy)
            return;
        if (await _vm.SignInAsync(PasswordBox.Password))
        {
            DialogResult = true;
            return;
        }
        if (_vm.NeedsCode)
        {
            PasswordBox.Clear();
            CodeBox.Focus();
        }
    }

    private async void OnConfirm(object sender, RoutedEventArgs e)
    {
        if (_vm.IsBusy)
            return;
        if (await _vm.ConfirmCodeAsync())
            DialogResult = true;
        else if (_vm.NeedsCode)
        {
            CodeBox.SelectAll();
            CodeBox.Focus();
        }
        else
            PasswordBox.Focus();
    }

    private void OnBack(object sender, RoutedEventArgs e)
    {
        _vm.BackToCredentials();
        PasswordBox.Focus();
    }

    private void OnPasswordKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnSignIn(sender, e);
    }

    private void OnCodeKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            OnConfirm(sender, e);
    }
}
