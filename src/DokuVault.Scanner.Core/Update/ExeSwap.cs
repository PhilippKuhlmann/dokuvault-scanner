namespace DokuVault.Scanner.Core.Update;

/// <summary>
/// Replaces the exe from outside. A running single-file exe must stay where it
/// is: the runtime reads assemblies from that path as it needs them, and after
/// a rename or swap it fails on the next one. So the download starts as
/// "X.update.exe", waits for "X.exe" to end, and then copies itself over it.
/// </summary>
public static class ExeSwap
{
    private const string UpdateSuffix = ".update.exe";

    public static string UpdatePath(string exe) => Path.ChangeExtension(exe, UpdateSuffix);

    /// <summary>"X.exe" for "X.update.exe", null for any other name.</summary>
    public static string? TargetOf(string updateExe) =>
        updateExe.EndsWith(UpdateSuffix, StringComparison.OrdinalIgnoreCase)
            ? updateExe[..^UpdateSuffix.Length] + ".exe"
            : null;

    private static string CopyPath(string target) => target + ".new";

    /// <summary>
    /// Copy first, then one atomic move: whatever fails, the old exe stays
    /// whole. A second running instance blocks the move until the attempts run
    /// out, and the next start tries again.
    /// </summary>
    public static void Install(string updateExe, int attempts = 40, int pauseMilliseconds = 250)
    {
        var target = TargetOf(updateExe) ?? throw new ArgumentException("Not an update file.", nameof(updateExe));
        var copy = CopyPath(target);
        try
        {
            File.Copy(updateExe, copy, overwrite: true);
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    File.Move(copy, target, overwrite: true);
                    return;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException && attempt < attempts)
                {
                    Thread.Sleep(pauseMilliseconds);
                }
            }
        }
        catch
        {
            TryDelete(copy);
            throw;
        }
    }

    /// <summary>
    /// Removes what an update left behind. Never throws. The first try runs
    /// before the caller goes on; more attempts are for the restart, when the
    /// update process is still ending, and must not run beside a new download.
    /// </summary>
    public static async Task RemoveLeftoversAsync(string exe, int attempts, int pauseMilliseconds = 250)
    {
        TryDelete(CopyPath(exe));
        for (int i = 1; !TryDelete(UpdatePath(exe)) && i < attempts; i++)
            await Task.Delay(pauseMilliseconds).ConfigureAwait(false);
    }

    private static bool TryDelete(string path)
    {
        try
        {
            File.Delete(path);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}
