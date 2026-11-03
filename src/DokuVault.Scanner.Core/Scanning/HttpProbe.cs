using System.Net;
using System.Net.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace DokuVault.Scanner.Core.Scanning;

public sealed record HttpInfo(string Url, int Status, string? Server, string? Title);

/// <summary>
/// Reads the title and Server header of a device's web interface. The
/// client accepts any certificate: devices carry self-signed ones, and
/// nothing is sent - it only reads the start page. It must never be used
/// for the DokuVault server.
/// </summary>
public sealed partial class HttpProbe : IDisposable
{
    private const int MaxBody = 64 * 1024;
    private readonly HttpClient _http;

    public HttpProbe()
    {
        var handler = new SocketsHttpHandler
        {
            // Straight to the device, never through a proxy; redirects are
            // followed by hand and only on the same device.
            UseProxy = false,
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(2),
            PooledConnectionLifetime = TimeSpan.FromSeconds(10),
            UseCookies = false,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
        };
        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("DokuVaultScanner/1.0");
    }

    public async Task<HttpInfo?> ProbeAsync(IPAddress address, int port, bool tls, CancellationToken cancellationToken)
    {
        var start = new Uri($"{(tls ? "https" : "http")}://{address}{((tls && port == 443) || (!tls && port == 80) ? "" : ":" + port)}/");
        // HttpClient.Timeout ends with the headers; the body needs its own limit.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(6));
        var token = cts.Token;
        try
        {
            var url = start;
            for (int hop = 0; ; hop++)
            {
                using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, token);
                int status = (int)response.StatusCode;
                if (status is >= 300 and < 400 && hop < 3 && response.Headers.Location is { } location)
                {
                    var next = location.IsAbsoluteUri ? location : new Uri(url, location);
                    if (next.Host == address.ToString() && next.Scheme is "http" or "https")
                    {
                        url = next;
                        continue;
                    }
                }

                string? server = response.Headers.Server.Count > 0 ? response.Headers.Server.ToString() : null;
                string? title = null;
                var mediaType = response.Content.Headers.ContentType?.MediaType;
                if (mediaType is null || mediaType.Contains("html", StringComparison.OrdinalIgnoreCase))
                {
                    await using var stream = await response.Content.ReadAsStreamAsync(token);
                    var buffer = new byte[MaxBody];
                    int total = 0, read;
                    while (total < buffer.Length &&
                           (read = await stream.ReadAsync(buffer.AsMemory(total), token)) > 0)
                        total += read;
                    title = ExtractTitle(Encoding.UTF8.GetString(buffer, 0, total));
                }
                // The address as typed in a browser, not the page it led to.
                return new HttpInfo(start.ToString(), status, server, title);
            }
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    internal static string? ExtractTitle(string html)
    {
        var match = TitleRegex().Match(html);
        if (!match.Success)
            return null;
        var title = WebUtility.HtmlDecode(WhitespaceRegex().Replace(match.Groups[1].Value, " ")).Trim();
        return title.Length is 0 or > 200 ? null : title;
    }

    [GeneratedRegex(@"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex TitleRegex();

    [GeneratedRegex(@"\s+")]
    private static partial Regex WhitespaceRegex();

    public void Dispose() => _http.Dispose();
}
