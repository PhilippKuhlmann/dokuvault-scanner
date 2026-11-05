using System.Diagnostics;
using System.IO;
using System.Windows;
using DokuVault.Scanner.Core.Update;
using DokuVault.Scanner.Views;

namespace DokuVault.Scanner.Infrastructure;

/// <summary>
/// Runs at every start, before the app talks to the DokuVault server. A newer
/// release is downloaded and started as "X.update.exe", which reports back,
/// replaces "X.exe" once this process has ended and starts it. Being offline
/// shows nothing; a failed update says so and the app starts as it is. A new
/// version that does not even start never replaces the old one.
/// </summary>
public static class AppUpdater
{
    private const string InstallArgument = "--install-update";
    /// <summary>Set for the restart: the new version does not look again at once.</summary>
    private const string RestartArgument = "--updated";

    private static readonly TimeSpan CheckLimit = TimeSpan.FromSeconds(4);
    private static readonly TimeSpan DownloadLimit = TimeSpan.FromMinutes(10);
    /// <summary>Generous: a virus scanner may look at a new exe for a while.</summary>
    private static readonly TimeSpan StartLimit = TimeSpan.FromSeconds(30);

    public static Version Current { get; } = typeof(AppUpdater).Assembly.GetName().Version ?? new Version(0, 0, 0);

    /// <summary>True: this process should end, another one takes over.</summary>
    public static async Task<bool> TryUpdateAsync(string[] args, UpdateClient? client = null)
    {
        if (UpdatableExe() is not { } exe)
            return false;

        int install = Array.IndexOf(args, InstallArgument);
        if (install >= 0 && ExeSwap.TargetOf(exe) is { } target)
        {
            await InstallAsync(exe, target, install + 1 < args.Length ? args[install + 1] : null);
            return true;
        }

        bool restarted = args.Contains(RestartArgument);
        _ = ExeSwap.RemoveLeftoversAsync(exe, attempts: restarted ? 40 : 1);
        if (restarted)
            return false;

        using var updates = client ?? new UpdateClient();
        using var checkLimit = new CancellationTokenSource(CheckLimit);
        if (await updates.CheckAsync(Current, checkLimit.Token) is not { } update)
            return false;

        var window = new UpdateWindow(update.Version);
        window.Show();
        try
        {
            using var downloadLimit = CancellationTokenSource.CreateLinkedTokenSource(window.Skipped);
            downloadLimit.CancelAfter(DownloadLimit);
            await updates.DownloadAsync(update, ExeSwap.UpdatePath(exe), window.Progress, downloadLimit.Token);
            window.Skipped.ThrowIfCancellationRequested();

            window.ShowInstalling();
            await StartUpdateAsync(exe);
            return true;
        }
        catch (OperationCanceledException) when (window.Skipped.IsCancellationRequested)
        {
            TryRemove(ExeSwap.UpdatePath(exe));
            return false;
        }
        catch (Exception e)
        {
            TryRemove(ExeSwap.UpdatePath(exe));
            await window.ShowErrorAsync(Describe(e, exe));
            return false;
        }
        finally
        {
            window.Close();
        }
    }

    /// <summary>
    /// The path of a published single-file exe. A build from the IDE has its dll
    /// beside it, and a test build carries version 0.0.0: both stay as they are.
    /// </summary>
    private static string? UpdatableExe()
    {
        var exe = Environment.ProcessPath;
        return exe is null || Current.Major + Current.Minor + Current.Build == 0 || File.Exists(Path.ChangeExtension(exe, ".dll"))
            ? null
            : exe;
    }

    private static async Task StartUpdateAsync(string exe)
    {
        int self = Environment.ProcessId;
        using var started = new EventWaitHandle(false, EventResetMode.ManualReset, SignalName(self));
        var info = new ProcessStartInfo(ExeSwap.UpdatePath(exe))
        {
            UseShellExecute = false,
            WorkingDirectory = Path.GetDirectoryName(exe)!,
        };
        info.ArgumentList.Add(InstallArgument);
        info.ArgumentList.Add(self.ToString());
        using var update = Process.Start(info) ?? throw new UpdateException("Die neue Version ließ sich nicht starten.");

        bool reported = await Task.Run(() =>
        {
            var clock = Stopwatch.StartNew();
            while (!started.WaitOne(200))
            {
                if (update.HasExited || clock.Elapsed > StartLimit)
                    return false;
            }
            return true;
        });
        if (reported)
            return;

        if (!update.HasExited)
        {
            update.Kill();
            update.WaitForExit(2000);
        }
        throw new UpdateException("Die neue Version ließ sich nicht starten.");
    }

    /// <summary>Runs as "X.update.exe": says it works, waits for the old process, takes its place.</summary>
    private static async Task InstallAsync(string updateExe, string target, string? parent)
    {
        try
        {
            if (int.TryParse(parent, out int id))
            {
                if (EventWaitHandle.TryOpenExisting(SignalName(id), out var started))
                {
                    using (started)
                        started.Set();
                }
                await Task.Run(() => WaitForExit(id));
            }
            await Task.Run(() => ExeSwap.Install(updateExe));
        }
        catch (Exception e)
        {
            MessageBox.Show(
                $"Das Update konnte nicht installiert werden: {e.Message}\n\nLäuft der Scanner noch in einem anderen Fenster? Er startet jetzt in der bisherigen Version und versucht es beim nächsten Start erneut.",
                "DokuVault Scanner", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        try
        {
            Process.Start(new ProcessStartInfo(target, RestartArgument)
            {
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(target)!,
            })?.Dispose();
        }
        catch (Exception e)
        {
            MessageBox.Show($"Der Scanner ließ sich nicht neu starten: {e.Message}", "DokuVault Scanner", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void WaitForExit(int id)
    {
        try
        {
            using var process = Process.GetProcessById(id);
            process.WaitForExit(30_000);
        }
        catch (ArgumentException)
        {
            // Already gone.
        }
    }

    private static string SignalName(int processId) => $"DokuVaultScanner-Update-{processId}";

    private static string Describe(Exception e, string exe) => e switch
    {
        UnauthorizedAccessException => $"Das Update konnte nicht installiert werden: keine Schreibrechte im Ordner {Path.GetDirectoryName(exe)}.",
        OperationCanceledException => "Das Update hat zu lange gedauert und wurde abgebrochen.",
        _ => $"Das Update konnte nicht installiert werden: {e.Message}",
    };

    private static void TryRemove(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
