namespace DokuVault.Scanner.Core;

public static class AppPaths
{
    /// <summary>%LOCALAPPDATA%\DokuVault Scanner - settings, token, manufacturer list.</summary>
    public static string DataDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DokuVault Scanner");
}
