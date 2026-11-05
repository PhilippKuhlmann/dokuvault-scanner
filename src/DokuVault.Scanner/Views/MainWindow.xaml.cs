using System.ComponentModel;
using System.Windows;
using DokuVault.Scanner.Infrastructure;
using DokuVault.Scanner.ViewModels;

namespace DokuVault.Scanner.Views;

public partial class MainWindow : Window
{
    private readonly MainViewModel _vm;
    private bool _closingForSignOut;

    public MainWindow(MainViewModel vm)
    {
        InitializeComponent();
        DataContext = _vm = vm;
        Title = $"DokuVault Scanner {AppUpdater.Current.ToString(3)}";
        ThemeManager.Attach(this);
        ShowTheme();
        ThemeManager.Changed += ShowTheme;
        Closed += (_, _) => ThemeManager.Changed -= ShowTheme;
    }

    /// <summary>The icon shows the current mode: monitor, sun, moon.</summary>
    private void ShowTheme()
    {
        ThemeButton.Content = ThemeManager.Mode switch
        {
            AppTheme.Light => "",
            AppTheme.Dark => "",
            _ => "",
        };
        ThemeButton.ToolTip = $"Darstellung: {ThemeManager.Label(ThemeManager.Mode)} – klicken zum Wechseln (Strg+Umschalt+D: hell/dunkel)";
    }

    public event Func<Task>? SignOutRequested;

    public void CloseForSignOut()
    {
        _closingForSignOut = true;
        Close();
    }

    private void OnSignOut(object sender, RoutedEventArgs e)
    {
        if (_vm.IsImporting)
            return;
        SignOutRequested?.Invoke();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (_vm.IsImporting && !_closingForSignOut)
        {
            var answer = MessageBox.Show(this,
                "Es werden gerade Geräte übernommen. Trotzdem beenden? Ein Gerät kann dann ohne IP-Adresse angelegt bleiben.",
                "DokuVault Scanner", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes)
            {
                e.Cancel = true;
                return;
            }
        }
        _vm.CancelAll();
        _vm.SaveSettings();
        base.OnClosing(e);
    }
}
