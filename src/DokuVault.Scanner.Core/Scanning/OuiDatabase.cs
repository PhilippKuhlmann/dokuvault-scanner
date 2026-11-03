using System.Text;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// Manufacturer by MAC prefix, from the IEEE registries: MA-L (first three
/// bytes), MA-M (28 bits) and MA-S (36 bits) - many small IoT makers only
/// hold an MA-M or MA-S block, under the MA-L "IEEE Registration Authority".
/// The lists are about 7 MB, so they are not shipped: they are fetched from
/// the IEEE and kept in the user's profile, renewed after 90 days. Without
/// them the scan still works, only without manufacturers.
/// </summary>
public sealed class OuiDatabase
{
    public static readonly IReadOnlyList<(string Url, string File)> Sources = new[]
    {
        ("https://standards-oui.ieee.org/oui/oui.csv", "oui.csv"),
        ("https://standards-oui.ieee.org/oui28/mam.csv", "mam.csv"),
        ("https://standards-oui.ieee.org/oui36/oui36.csv", "oui36.csv"),
    };

    private static readonly TimeSpan MaxAge = TimeSpan.FromDays(90);

    private readonly Dictionary<string, string> _vendors;

    private OuiDatabase(Dictionary<string, string> vendors) => _vendors = vendors;

    public static OuiDatabase Empty { get; } = new(new Dictionary<string, string>());

    public int Count => _vendors.Count;

    public static string CachePath(string file) => Path.Combine(AppPaths.DataDirectory, file);

    internal static OuiDatabase FromLines(IEnumerable<string> lines) => new(Parse(lines));

    /// <summary>The longest registered prefix wins: MA-S, then MA-M, then MA-L.</summary>
    public string? Lookup(string? mac)
    {
        if (!ArpResolver.TryParse(mac, out var bytes))
            return null;
        if ((bytes[0] & 0x02) != 0)
            return null; // randomised, see ArpResolver.IsRandomized
        var hex = Convert.ToHexString(bytes);
        foreach (int length in new[] { 9, 7, 6 })
            if (_vendors.TryGetValue(hex[..length], out var vendor))
                return vendor;
        return null;
    }

    /// <summary>The cached lists, downloaded first when missing or stale. Never throws.</summary>
    public static async Task<(OuiDatabase Database, string? Problem)> LoadAsync(
        HttpClient http, bool forceDownload, CancellationToken cancellationToken)
    {
        string? problem = null;
        var vendors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (url, file) in Sources)
        {
            var path = CachePath(file);
            bool stale = !File.Exists(path) || DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > MaxAge;
            if (stale || forceDownload)
            {
                var error = await DownloadAsync(http, url, path, cancellationToken);
                // MA-L matters most; the small lists failing is worth no warning.
                if (error is not null && file == "oui.csv")
                    problem = error;
            }
            if (!File.Exists(path))
                continue;
            try
            {
                foreach (var (key, value) in Parse(File.ReadLines(path, Encoding.UTF8)))
                    vendors[key] = value;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                problem ??= $"Herstellerliste unlesbar: {e.Message}";
            }
        }
        if (vendors.Count == 0)
            return (Empty, problem ?? "Keine Herstellerliste vorhanden.");
        return (new OuiDatabase(vendors), problem);
    }

    private static async Task<string?> DownloadAsync(HttpClient http, string url, string path, CancellationToken cancellationToken)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            // The IEEE server rejects requests without a browser-like agent.
            request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) DokuVaultScanner/1.0");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMinutes(2));
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            response.EnsureSuccessStatusCode();
            var temp = path + ".download";
            await using (var file = File.Create(temp))
                await response.Content.CopyToAsync(file, cts.Token);
            // Only replace a working list with one that parses.
            if (Parse(File.ReadLines(temp, Encoding.UTF8)).Count > 100)
            {
                File.Move(temp, path, overwrite: true);
                return null;
            }
            File.Delete(temp);
            return "Die Herstellerliste der IEEE war unvollständig.";
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception e)
        {
            return $"Herstellerliste nicht aktualisiert: {e.Message}";
        }
    }

    /// <summary>
    /// "Registry,Assignment,Organization Name,Organization Address" -
    /// quoted where a name holds a comma. Assignment: 6, 7 or 9 hex digits.
    /// </summary>
    public static Dictionary<string, string> Parse(IEnumerable<string> lines)
    {
        var vendors = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines)
        {
            var fields = SplitCsv(line);
            if (fields.Count < 3 || fields[1].Length is not (6 or 7 or 9) || !fields[1].All(Uri.IsHexDigit))
                continue;
            var name = fields[2].Trim();
            if (name.Length > 0)
                vendors[fields[1].ToUpperInvariant()] = name;
        }
        return vendors;
    }

    internal static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var current = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < line.Length && line[i + 1] == '"')
                {
                    current.Append('"');
                    i++;
                }
                else if (c == '"')
                    quoted = false;
                else
                    current.Append(c);
            }
            else if (c == '"')
                quoted = true;
            else if (c == ',')
            {
                fields.Add(current.ToString());
                current.Clear();
            }
            else
                current.Append(c);
        }
        fields.Add(current.ToString());
        return fields;
    }
}
