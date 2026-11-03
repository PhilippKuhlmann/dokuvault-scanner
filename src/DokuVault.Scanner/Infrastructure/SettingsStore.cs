using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DokuVault.Scanner.Core;

namespace DokuVault.Scanner.Infrastructure;

public sealed class AppSettings
{
    public string? ServerUrl { get; set; }
    public string? Username { get; set; }
    public string? Customer { get; set; }
    public string? Range { get; set; }
    public string SnmpCommunity { get; set; } = "public";
    public bool UseSnmp { get; set; } = true;
    public bool HideDocumented { get; set; }

    /// <summary>"System", "Light" or "Dark".</summary>
    public string Theme { get; set; } = "System";

    /// <summary>Last chosen site per customer slug.</summary>
    public Dictionary<string, string> Sites { get; set; } = new();
}

/// <summary>
/// Settings as JSON and the token encrypted with DPAPI for the current
/// Windows user, both in %LOCALAPPDATA%\DokuVault Scanner. The password is
/// never stored.
/// </summary>
public static class SettingsStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("DokuVault.Scanner.Token.v1");
    private static string SettingsPath => Path.Combine(AppPaths.DataDirectory, "settings.json");
    private static string TokenPath => Path.Combine(AppPaths.DataDirectory, "token.bin");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) ?? new AppSettings();
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException)
        {
        }
        return new AppSettings();
    }

    public static void Save(AppSettings settings)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }

    public static (string Server, string Token)? LoadToken()
    {
        try
        {
            if (!File.Exists(TokenPath))
                return null;
            var plain = ProtectedData.Unprotect(File.ReadAllBytes(TokenPath), Entropy, DataProtectionScope.CurrentUser);
            var text = Encoding.UTF8.GetString(plain);
            int split = text.IndexOf('\n');
            return split > 0 ? (text[..split], text[(split + 1)..]) : null;
        }
        catch (Exception e) when (e is IOException or CryptographicException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>The token is bound to the server it came from.</summary>
    public static void SaveToken(string server, string token)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
            var data = ProtectedData.Protect(Encoding.UTF8.GetBytes(server + "\n" + token), Entropy, DataProtectionScope.CurrentUser);
            File.WriteAllBytes(TokenPath, data);
        }
        catch (Exception e) when (e is IOException or CryptographicException or UnauthorizedAccessException)
        {
        }
    }

    public static void DeleteToken()
    {
        try
        {
            File.Delete(TokenPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
