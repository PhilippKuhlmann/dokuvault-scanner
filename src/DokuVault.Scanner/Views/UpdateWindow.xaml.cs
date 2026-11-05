using System.Windows;
using DokuVault.Scanner.Infrastructure;

namespace DokuVault.Scanner.Views;

public partial class UpdateWindow : Window
{
    private static readonly TimeSpan ErrorShownFor = TimeSpan.FromSeconds(8);

    private readonly CancellationTokenSource _skipped = new();
    private readonly Version _version;

    public UpdateWindow(Version version)
    {
        InitializeComponent();
        _version = version;
        ThemeManager.Attach(this);
        Versions.Text = $"Update von {AppUpdater.Current.ToString(3)} auf {version.ToString(3)}";
        Message.Text = $"Version {version.ToString(3)} wird geladen …";
        Progress = new Progress<double>(value => Bar.Value = value);
        Closed += (_, _) => _skipped.Cancel();
    }

    /// <summary>Set by the button or by closing the window.</summary>
    public CancellationToken Skipped => _skipped.Token;

    public IProgress<double> Progress { get; }

    public void ShowInstalling()
    {
        Message.Text = $"Version {_version.ToString(3)} wird installiert …";
        Bar.Value = Bar.Maximum;
        Action.IsEnabled = false;
    }

    /// <summary>Shows the error for a few seconds or until "Weiter", then the app starts anyway.</summary>
    public async Task ShowErrorAsync(string message)
    {
        Message.Text = message;
        Message.Foreground = (System.Windows.Media.Brush)FindResource("Danger");
        Bar.Visibility = Visibility.Collapsed;
        Action.Content = "Weiter";
        Action.IsEnabled = true;
        try
        {
            await Task.Delay(ErrorShownFor, _skipped.Token);
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void OnAction(object sender, RoutedEventArgs e) => _skipped.Cancel();
}
