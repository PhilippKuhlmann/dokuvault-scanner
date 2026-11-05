using System.Windows;
using System.Windows.Threading;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Infrastructure;
using DokuVault.Scanner.ViewModels;
using DokuVault.Scanner.Views;

namespace DokuVault.Scanner;

public partial class App : Application
{
    private AppSettings _settings = new();

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;
        // The sweep runs a few hundred short tasks at once; a cold thread
        // pool would add threads only slowly.
        ThreadPool.GetMinThreads(out int workers, out int io);
        ThreadPool.SetMinThreads(Math.Max(workers, 64), Math.Max(io, 64));

        _settings = SettingsStore.Load();
        ThemeManager.Apply(ThemeManager.Parse(_settings.Theme));
        ThemeManager.Changed += () =>
        {
            _settings.Theme = ThemeManager.Mode.ToString();
            SettingsStore.Save(_settings);
        };

        if (await AppUpdater.TryUpdateAsync(e.Args))
        {
            Shutdown();
            return;
        }

        var session = await ResumeAsync();
        ShowMain(session, null);
    }

    /// <summary>The stored token, if the server still takes it.</summary>
    private async Task<(DokuVaultClient Client, User User)?> ResumeAsync()
    {
        if (SettingsStore.LoadToken() is not { } stored ||
            !DokuVaultClient.TryParseServerUrl(stored.Server, out var url, out _))
            return null;
        var client = new DokuVaultClient(url!, stored.Token);
        try
        {
            var user = await client.MeAsync(CancellationToken.None);
            return (client, user);
        }
        catch (DokuVaultApiException e)
        {
            client.Dispose();
            if (e.IsUnauthorized)
                SettingsStore.DeleteToken();
            return null;
        }
    }

    private void ShowMain((DokuVaultClient Client, User User)? session, string? notice)
    {
        while (session is null)
        {
            var login = new LoginViewModel(_settings, notice);
            var window = new LoginWindow(login);
            if (window.ShowDialog() != true || login.Result is null)
            {
                Shutdown();
                return;
            }
            session = login.Result;
        }

        var vm = new MainViewModel(session.Value.Client, session.Value.User, _settings);
        var main = new MainWindow(vm);
        MainWindow = main;
        bool signingOut = false;
        vm.SignedOut += () =>
        {
            if (signingOut)
                return;
            signingOut = true;
            SettingsStore.DeleteToken();
            main.CloseForSignOut();
            ShowMain(null, "Die Anmeldung ist abgelaufen. Bitte neu anmelden.");
        };
        main.SignOutRequested += async () =>
        {
            if (signingOut)
                return;
            signingOut = true;
            await vm.Client.LogoutAsync(CancellationToken.None);
            SettingsStore.DeleteToken();
            main.CloseForSignOut();
            ShowMain(null, null);
        };
        main.Closed += (_, _) =>
        {
            if (!signingOut)
                Shutdown();
        };
        main.Show();
        _ = vm.InitializeAsync();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(e.Exception.Message, "DokuVault Scanner – Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
