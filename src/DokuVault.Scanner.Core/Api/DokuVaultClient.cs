using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Core.Api;

/// <summary>A failed call, with the server's message where it sent one.</summary>
public sealed class DokuVaultApiException : Exception
{
    public HttpStatusCode Status { get; }
    public IReadOnlyDictionary<string, string[]> FieldErrors { get; }

    public DokuVaultApiException(HttpStatusCode status, string message, IReadOnlyDictionary<string, string[]>? fieldErrors = null)
        : base(message)
    {
        Status = status;
        FieldErrors = fieldErrors ?? new Dictionary<string, string[]>();
    }

    public bool IsUnauthorized => Status == HttpStatusCode.Unauthorized;

    /// <summary>The first message on a field, or the general message.</summary>
    public string FieldMessage(string field) =>
        FieldErrors.TryGetValue(field, out var errors) && errors.Length > 0 ? errors[0] : Message;
}

/// <summary>
/// The client for DokuVault's /api/mobile - the same interface the iOS app
/// uses, with the same permissions as the browser. Only https, except for
/// a development host (localhost, *.test).
/// </summary>
public sealed partial class DokuVaultClient : IDisposable
{
    public static readonly string UserAgent =
        $"DokuVault-Scanner/{Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0"} (Windows)";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private string? _token;

    public DokuVaultClient(Uri serverUrl, string? token = null, HttpMessageHandler? handler = null)
    {
        ServerUrl = NormalizeServerUrl(serverUrl);
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.BaseAddress = new Uri(ServerUrl, "api/mobile/");
        _http.Timeout = TimeSpan.FromSeconds(30);
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        _http.DefaultRequestHeaders.AcceptLanguage.Add(new StringWithQualityHeaderValue("de"));
        _http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        _token = token;
    }

    /// <summary>The server's root, always ending in a slash.</summary>
    public Uri ServerUrl { get; }

    public string? Token => _token;

    public bool IsSignedIn => _token is not null;

    /// <summary>
    /// "dokuvault.firma.de" → https://dokuvault.firma.de/. A path is kept
    /// (installation under a sub path), a trailing "/api/mobile" is not.
    /// </summary>
    public static Uri NormalizeServerUrl(Uri url)
    {
        var text = url.ToString().TrimEnd('/');
        foreach (var suffix in new[] { "/api/mobile", "/api" })
            if (text.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                text = text[..^suffix.Length];
        var normalized = new Uri(text + "/");
        if (normalized.Scheme != Uri.UriSchemeHttps && !IsDevelopmentHost(normalized.Host))
            throw new ArgumentException("Der Server muss per https erreichbar sein.");
        return normalized;
    }

    public static bool TryParseServerUrl(string? text, out Uri? url, out string? error)
    {
        url = null;
        error = null;
        text = text?.Trim();
        if (string.IsNullOrEmpty(text))
        {
            error = "Bitte die Adresse des DokuVault-Servers eingeben.";
            return false;
        }
        if (!text.Contains("://"))
            text = "https://" + text;
        if (!Uri.TryCreate(text, UriKind.Absolute, out var parsed) ||
            (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            error = "Das ist keine gültige Serveradresse.";
            return false;
        }
        try
        {
            url = NormalizeServerUrl(parsed);
            return true;
        }
        catch (ArgumentException e)
        {
            error = e.Message;
            return false;
        }
    }

    private static bool IsDevelopmentHost(string host) =>
        host is "localhost" or "127.0.0.1" or "[::1]" ||
        host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase) ||
        host.EndsWith(".test", StringComparison.OrdinalIgnoreCase);

    // ---- sign-in --------------------------------------------------------

    /// <summary>Either a token (then signed in) or a second-factor challenge.</summary>
    public async Task<TokenResponse> LoginAsync(string username, string password, string device, CancellationToken cancellationToken)
    {
        var response = await SendAsync<TokenResponse>(HttpMethod.Post, "login",
            new Dictionary<string, object?> { ["username"] = username, ["password"] = password, ["device"] = device },
            authenticated: false, cancellationToken);
        if (response.Token is not null)
            _token = response.Token;
        return response;
    }

    public async Task<TokenResponse> LoginTwoFactorAsync(string challenge, string code, CancellationToken cancellationToken)
    {
        var response = await SendAsync<TokenResponse>(HttpMethod.Post, "login/two-factor",
            new Dictionary<string, object?> { ["challenge"] = challenge, ["code"] = code.Trim() },
            authenticated: false, cancellationToken);
        _token = response.Token;
        return response;
    }

    /// <summary>Revokes only this app's token. Best effort - the token is forgotten either way.</summary>
    public async Task LogoutAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (_token is not null)
                await SendAsync<JsonElement?>(HttpMethod.Post, "logout", null, authenticated: true, cancellationToken);
        }
        catch (Exception e) when (e is DokuVaultApiException or HttpRequestException)
        {
        }
        finally
        {
            _token = null;
        }
    }

    public Task<User> MeAsync(CancellationToken cancellationToken) =>
        SendAsync<User>(HttpMethod.Get, "me", null, authenticated: true, cancellationToken);

    // ---- reading --------------------------------------------------------

    public Task<List<Customer>> CustomersAsync(CancellationToken cancellationToken) =>
        SendAsync<List<Customer>>(HttpMethod.Get, "customers", null, true, cancellationToken);

    /// <summary>The empty form of a type: fields, sites, defaults. 403 without {type}_create.</summary>
    public Task<ObjectForm> CreateFormAsync(string customer, string type, CancellationToken cancellationToken) =>
        SendAsync<ObjectForm>(HttpMethod.Get, $"customers/{Esc(customer)}/forms/{Esc(type)}", null, true, cancellationToken);

    public Task<NetworkList> NetworksAsync(string customer, CancellationToken cancellationToken) =>
        SendAsync<NetworkList>(HttpMethod.Get, $"customers/{Esc(customer)}/networks", null, true, cancellationToken);

    public Task<NetworkDetail> NetworkAsync(string customer, int id, CancellationToken cancellationToken) =>
        SendAsync<NetworkDetail>(HttpMethod.Get, $"customers/{Esc(customer)}/networks/{id}", null, true, cancellationToken);

    public Task<List<SearchGroup>> SearchAsync(string query, CancellationToken cancellationToken) =>
        SendAsync<List<SearchGroup>>(HttpMethod.Get, $"search?q={Uri.EscapeDataString(query)}", null, true, cancellationToken);

    public Task<ObjectDetail> ObjectAsync(string type, int id, CancellationToken cancellationToken) =>
        SendAsync<ObjectDetail>(HttpMethod.Get, $"objects/{Esc(type)}/{id}", null, true, cancellationToken);

    /// <summary>
    /// Every address the customer has documented in an IP plan: one call for
    /// the VLANs, one per VLAN. Needs network_viewAny (otherwise 403).
    /// "Covered" are the VLANs whose plan was read completely; an address
    /// outside them has to be checked one by one with <see cref="FindDocumentedAsync"/>.
    /// </summary>
    public async Task<DocumentedSet> DocumentedAddressesAsync(string customer, CancellationToken cancellationToken)
    {
        var warnings = new List<string>();
        var networks = (await NetworksAsync(customer, cancellationToken)).Entries.ToList();
        var covered = new List<NetworkEntry>();
        var result = new List<DocumentedAddress>();
        foreach (var network in networks.Where(n => n.Error is null))
        {
            NetworkDetail detail;
            try
            {
                detail = await NetworkAsync(customer, network.Id, cancellationToken);
            }
            catch (DokuVaultApiException e) when (!e.IsUnauthorized)
            {
                // One unreadable plan costs only that VLAN, not the whole check.
                warnings.Add($"IP-Plan von „{network.Name}“ nicht lesbar: {e.Message}");
                continue;
            }
            if (detail.Truncated.ValueKind == JsonValueKind.True)
                warnings.Add($"Der IP-Plan von „{network.Name}“ ist gekürzt – dort wird einzeln geprüft.");
            else
                covered.Add(network);
            result.AddRange(PlanAddresses(detail));
        }
        return new DocumentedSet(result, networks, covered, warnings);
    }

    internal static IEnumerable<DocumentedAddress> PlanAddresses(NetworkDetail detail)
    {
        foreach (var row in detail.Rows ?? Array.Empty<PlanRow>())
        {
            if (row.Kind == "device" && row.From is not null)
            {
                var devices = row.Devices ?? Array.Empty<PlanDevice>();
                // The gateway gets a row of its own even when no device holds it.
                if (devices.Count == 0)
                {
                    if (!row.Gateway)
                        yield return new DocumentedAddress(row.From, null, null, null, detail.Id, detail.Name);
                    continue;
                }
                foreach (var d in devices)
                    yield return new DocumentedAddress(row.From, d.Name, d.Type, d.Id, detail.Id, detail.Name);
            }
            else if (row.Kind == "dhcp")
            {
                // Fixed addresses inside the pool: "Name (192.168.1.50)".
                foreach (var d in (row.Devices ?? Array.Empty<PlanDevice>()).Where(d => d.InPool))
                {
                    var match = TrailingAddress().Match(d.Name);
                    if (match.Success)
                        yield return new DocumentedAddress(match.Groups[2].Value, match.Groups[1].Value.Trim(),
                            d.Type, d.Id, detail.Id, detail.Name);
                }
            }
        }
    }

    [GeneratedRegex(@"^(.*)\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s*$")]
    private static partial Regex TrailingAddress();

    /// <summary>
    /// Fallback for one address: search, then confirm each hit exactly - the
    /// search matches substrings, 10.0.0.1 also finds 10.0.0.10.
    /// </summary>
    public async Task<DocumentedAddress?> FindDocumentedAsync(string customer, string address, CancellationToken cancellationToken)
    {
        var groups = await SearchAsync(address, cancellationToken);
        foreach (var hit in groups.SelectMany(g => g.Hits))
        {
            if (hit.Customer is not null && hit.Customer.Slug != customer)
                continue;
            try
            {
                var detail = await ObjectAsync(hit.Type, hit.Id, cancellationToken);
                if (detail.IpAddresses?.Any(ip => ip.Address == address) == true)
                    return new DocumentedAddress(address, detail.Name, detail.Type, detail.Id, null, null);
            }
            catch (DokuVaultApiException e) when (e.Status is HttpStatusCode.NotFound or HttpStatusCode.Forbidden)
            {
            }
        }
        return null;
    }

    // ---- writing --------------------------------------------------------

    /// <summary>
    /// Creates an object from form values. The keys are the field names of
    /// config/forms.php exactly as they are - "serialNumber" is camelCase,
    /// and the server silently drops keys it does not know.
    /// </summary>
    public Task<ObjectDetail> CreateObjectAsync(
        string customer, string type, IReadOnlyDictionary<string, object?> values, CancellationToken cancellationToken) =>
        SendAsync<ObjectDetail>(HttpMethod.Post, $"customers/{Esc(customer)}/{Esc(type)}", values, true, cancellationToken);

    /// <summary>A fixed address on the device. 422 on "address" when the customer already has it.</summary>
    public Task<List<IpEntry>> AddIpAddressAsync(
        string type, int id, string address, int? networkId, string? label, CancellationToken cancellationToken)
    {
        var body = new Dictionary<string, object?> { ["address"] = address };
        if (networkId is not null)
            body["network_id"] = networkId;
        if (!string.IsNullOrWhiteSpace(label))
            body["label"] = label;
        return SendAsync<List<IpEntry>>(HttpMethod.Post, $"objects/{Esc(type)}/{id}/ip-addresses", body, true, cancellationToken);
    }

    /// <summary>Into the trash - used to take back a half-created device.</summary>
    public Task DeleteObjectAsync(string type, int id, CancellationToken cancellationToken) =>
        SendAsync<JsonElement?>(HttpMethod.Delete, $"objects/{Esc(type)}/{id}", null, true, cancellationToken);

    /// <summary>The page of the type's list in the browser.</summary>
    public Uri BrowserListUrl(string customer, string type) => new(ServerUrl, $"{Esc(customer)}/{Esc(type)}");

    /// <summary>The VLAN of the customer whose subnet holds the address, preferring the site.</summary>
    public static NetworkEntry? MatchNetwork(IEnumerable<NetworkEntry> networks, IPAddress address, int? siteId)
    {
        NetworkEntry? best = null;
        int bestPrefix = -1;
        bool bestSite = false;
        foreach (var n in networks)
        {
            if (n.Error is not null || n.Network is null || !IpRange.TryParseV4(n.Network, out var net))
                continue;
            int prefix = n.Cidr ?? (n.SubnetMask is not null && IpRange.TryParseV4(n.SubnetMask, out var mask)
                ? IpRange.PrefixFromMask(mask)
                : -1);
            if (prefix is < 0 or > 32)
                continue;
            if (IpRange.NetworkOf(IpRange.ToUInt(address), prefix) != IpRange.NetworkOf(IpRange.ToUInt(net), prefix))
                continue;
            bool sameSite = siteId is not null && n.Site?.Id == siteId;
            // The same site beats a narrower subnet elsewhere: two sites may
            // use the same private range.
            if (best is null || (sameSite && !bestSite) || (sameSite == bestSite && prefix > bestPrefix))
            {
                best = n;
                bestPrefix = prefix;
                bestSite = sameSite;
            }
        }
        return best;
    }

    // ---- transport ------------------------------------------------------

    private static string Esc(string segment) => Uri.EscapeDataString(segment);

    private async Task<T> SendAsync<T>(HttpMethod method, string path, object? body, bool authenticated,
        CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            using var request = new HttpRequestMessage(method, path);
            if (authenticated)
            {
                if (_token is null)
                    throw new DokuVaultApiException(HttpStatusCode.Unauthorized, "Nicht angemeldet.");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            }
            if (body is not null)
                request.Content = JsonContent.Create(body, body.GetType(), options: Json);

            HttpResponseMessage response;
            try
            {
                response = await _http.SendAsync(request, cancellationToken);
            }
            catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new DokuVaultApiException(HttpStatusCode.RequestTimeout, "Der Server antwortet nicht (Zeitüberschreitung).");
            }
            catch (HttpRequestException e)
            {
                throw new DokuVaultApiException(0, $"Der Server ist nicht erreichbar: {e.Message}");
            }

            using (response)
            {
                // 60 requests a minute per user: wait as told, at most three
                // times. Safe for POST too - a 429 was not carried out.
                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < 3)
                {
                    var wait = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(10 * (attempt + 1));
                    await Task.Delay(wait > TimeSpan.FromSeconds(65) ? TimeSpan.FromSeconds(65) : wait, cancellationToken);
                    continue;
                }

                if (response.IsSuccessStatusCode)
                {
                    if (response.StatusCode == HttpStatusCode.NoContent || response.Content.Headers.ContentLength == 0)
                        return default!;
                    try
                    {
                        var result = await response.Content.ReadFromJsonAsync<T>(Json, cancellationToken);
                        return result!;
                    }
                    catch (JsonException)
                    {
                        throw new DokuVaultApiException(response.StatusCode,
                            "Die Antwort des Servers ist unlesbar – ist das wirklich ein DokuVault-Server?");
                    }
                }

                throw await ErrorAsync(response, cancellationToken);
            }
        }
    }

    private static async Task<DokuVaultApiException> ErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string? message = null;
        Dictionary<string, string[]>? errors = null;
        try
        {
            var text = await response.Content.ReadAsStringAsync(cancellationToken);
            if (text.Length > 0 && text.TrimStart().StartsWith('{'))
            {
                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                    message = m.GetString();
                if (doc.RootElement.TryGetProperty("errors", out var e) && e.ValueKind == JsonValueKind.Object)
                {
                    errors = new Dictionary<string, string[]>();
                    foreach (var field in e.EnumerateObject())
                        if (field.Value.ValueKind == JsonValueKind.Array)
                            errors[field.Name] = field.Value.EnumerateArray()
                                .Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToArray();
                }
            }
        }
        catch (JsonException)
        {
        }

        var status = response.StatusCode;
        // The first field message reads better than Laravel's "(and 2 more errors)".
        if (status == HttpStatusCode.UnprocessableEntity && errors?.Values.FirstOrDefault(v => v.Length > 0) is { } first)
            message = first[0];
        message ??= status switch
        {
            HttpStatusCode.Unauthorized => "Die Anmeldung ist abgelaufen. Bitte neu anmelden.",
            HttpStatusCode.Forbidden => "Dafür fehlt Ihnen das Recht.",
            HttpStatusCode.NotFound => "Nicht gefunden – oder kein DokuVault-Server unter dieser Adresse.",
            HttpStatusCode.TooManyRequests => "Zu viele Anfragen – bitte kurz warten.",
            _ when (int)status >= 500 => $"Fehler auf dem Server ({(int)status}).",
            _ => $"Unerwartete Antwort ({(int)status}).",
        };
        if (status == HttpStatusCode.Unauthorized)
            message = "Die Anmeldung ist abgelaufen. Bitte neu anmelden.";
        return new DokuVaultApiException(status, message, errors);
    }

    public void Dispose() => _http.Dispose();
}
