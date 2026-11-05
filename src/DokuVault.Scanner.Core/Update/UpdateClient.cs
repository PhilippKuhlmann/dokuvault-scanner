using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DokuVault.Scanner.Core.Update;

public sealed record AvailableUpdate(Version Version, string Tag);

public sealed class UpdateException(string message) : Exception(message);

/// <summary>
/// Asks GitHub for the latest release and fetches its exe. The URLs are built
/// from a strictly checked tag, not taken from the answer, so the exe can only
/// come from this repository's releases.
/// </summary>
public sealed partial class UpdateClient : IDisposable
{
    public const string ExeName = "DokuVaultScanner.exe";

    private static readonly Uri GitHubLatestRelease =
        new("https://api.github.com/repos/PhilippKuhlmann/dokuvault-scanner/releases/latest");
    private static readonly Uri GitHubDownloads =
        new("https://github.com/PhilippKuhlmann/dokuvault-scanner/releases/download/");

    private const long DefaultMaxExeBytes = 512L * 1024 * 1024;
    private const int ChecksumBytes = 1024;

    private readonly HttpClient _http;
    private readonly Uri _latestRelease;
    private readonly Uri _downloads;
    private readonly long _maxExeBytes;

    public UpdateClient(
        Uri? latestRelease = null,
        Uri? downloads = null,
        HttpMessageHandler? handler = null,
        long maxExeBytes = DefaultMaxExeBytes)
    {
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        // The callers set the limits: seconds for the check, minutes for the download.
        _http.Timeout = Timeout.InfiniteTimeSpan;
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("DokuVaultScanner", "1"));
        _latestRelease = latestRelease ?? GitHubLatestRelease;
        _downloads = downloads ?? GitHubDownloads;
        _maxExeBytes = maxExeBytes;
    }

    /// <summary>
    /// The latest release if it is newer than <paramref name="current"/>. Null
    /// on any failure too: without an answer the app simply starts as it is.
    /// </summary>
    public async Task<AvailableUpdate?> CheckAsync(Version current, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, _latestRelease);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return null;

            await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (json.RootElement.ValueKind != JsonValueKind.Object ||
                !json.RootElement.TryGetProperty("tag_name", out var tagName) ||
                tagName.ValueKind != JsonValueKind.String)
                return null;

            var tag = tagName.GetString()!;
            if (!TagFormat().IsMatch(tag))
                return null;
            var version = Version.Parse(tag[1..]);
            var installed = new Version(current.Major, current.Minor, Math.Max(current.Build, 0));
            return version > installed ? new AvailableUpdate(version, tag) : null;
        }
        catch (Exception e) when (e is HttpRequestException or OperationCanceledException or JsonException or IOException)
        {
            return null;
        }
    }

    /// <summary>
    /// Writes the exe to <paramref name="target"/> and compares it with the
    /// checksum of the release. Whatever fails, no file stays behind.
    /// </summary>
    public async Task DownloadAsync(AvailableUpdate update, string target, IProgress<double>? progress, CancellationToken ct)
    {
        // Opened first: a folder without write access should cost no download.
        var file = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        try
        {
            var expected = await ChecksumAsync(update, ct).ConfigureAwait(false);
            var actual = await CopyAsync(update, file, progress, ct).ConfigureAwait(false);
            await file.DisposeAsync().ConfigureAwait(false);
            if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                throw new UpdateException("Die Prüfsumme der geladenen Datei stimmt nicht.");
            // Starting anything else would stop at a modal Windows error box.
            if (!IsProgram(target))
                throw new UpdateException("Die Datei des Releases ist kein Programm.");
        }
        catch
        {
            await file.DisposeAsync().ConfigureAwait(false);
            TryDelete(target);
            throw;
        }
    }

    private async Task<string> ChecksumAsync(AvailableUpdate update, CancellationToken ct)
    {
        using var response = await GetAsync(update, ExeName + ".sha256", ct).ConfigureAwait(false);
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[ChecksumBytes];
        int length = await stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        var hash = System.Text.Encoding.ASCII.GetString(buffer, 0, length).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return hash is not null && ChecksumFormat().IsMatch(hash)
            ? hash
            : throw new UpdateException("Die Prüfsummendatei des Releases ist nicht lesbar.");
    }

    private async Task<string> CopyAsync(AvailableUpdate update, Stream file, IProgress<double>? progress, CancellationToken ct)
    {
        using var response = await GetAsync(update, ExeName, ct).ConfigureAwait(false);
        var length = response.Content.Headers.ContentLength;
        if (length > _maxExeBytes)
            throw new UpdateException("Die Datei des Releases ist unplausibel groß.");

        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long total = 0;
        int percent = -1;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > _maxExeBytes)
                throw new UpdateException("Die Datei des Releases ist unplausibel groß.");
            hash.AppendData(buffer, 0, read);
            await file.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
            if (length > 0 && (int)(total * 100 / length.Value) != percent)
            {
                percent = (int)(total * 100 / length.Value);
                progress?.Report(percent / 100d);
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private async Task<HttpResponseMessage> GetAsync(AvailableUpdate update, string fileName, CancellationToken ct)
    {
        var response = await _http.GetAsync(new Uri(_downloads, $"{update.Tag}/{fileName}"), HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (response.IsSuccessStatusCode)
            return response;
        var status = (int)response.StatusCode;
        response.Dispose();
        throw new UpdateException($"GitHub antwortet mit Status {status}.");
    }

    private static bool IsProgram(string path)
    {
        using var file = File.OpenRead(path);
        return file.ReadByte() == 'M' && file.ReadByte() == 'Z';
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }

    public void Dispose() => _http.Dispose();

    [GeneratedRegex(@"\Av[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\z")]
    private static partial Regex TagFormat();

    [GeneratedRegex(@"\A[0-9a-fA-F]{64}\z")]
    private static partial Regex ChecksumFormat();
}
