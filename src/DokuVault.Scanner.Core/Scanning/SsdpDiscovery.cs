using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>What a UPnP device describes about itself.</summary>
public sealed record UpnpInfo(
    string? Server,
    string? FriendlyName,
    string? Manufacturer,
    string? ModelName,
    string? ModelNumber,
    string? SerialNumber,
    string? DeviceType,
    IReadOnlyList<string> SearchTargets);

/// <summary>
/// UPnP/SSDP: one M-SEARCH into the LAN, then the description XML of every
/// device that answered. Smart TVs, media players, cameras, routers and many
/// IoT hubs say their manufacturer and model this way.
/// </summary>
public static class SsdpDiscovery
{
    private const int MaxDescription = 256 * 1024;
    private static readonly IPEndPoint Group = new(IPAddress.Parse("239.255.255.250"), 1900);

    // Straight to the device: no proxy, and no redirect that could lead the
    // request from the answering device to some other host.
    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        UseProxy = false,
        AllowAutoRedirect = false,
        UseCookies = false,
        ConnectTimeout = TimeSpan.FromSeconds(2),
    })
    {
        Timeout = TimeSpan.FromSeconds(4),
    };

    public static async Task<Dictionary<IPAddress, UpnpInfo>> DiscoverAsync(
        IEnumerable<IPAddress> localAddresses, Func<IPAddress, bool> inScope,
        TimeSpan listen, CancellationToken cancellationToken)
    {
        var responses = new Dictionary<IPAddress, (string? Location, string? Server, HashSet<string> Targets)>();
        await Task.WhenAll(localAddresses.Select(a => SearchOnAsync(a, listen, responses, cancellationToken)));

        var result = new Dictionary<IPAddress, UpnpInfo>();
        var fetches = responses
            .Where(r => inScope(r.Key))
            .Select(async r =>
            {
                var info = await DescribeAsync(r.Value.Location, r.Key, cancellationToken);
                var upnp = (info ?? new UpnpInfo(null, null, null, null, null, null, null, Array.Empty<string>())) with
                {
                    Server = r.Value.Server,
                    SearchTargets = r.Value.Targets.OrderBy(t => t).ToList(),
                };
                lock (result)
                    result[r.Key] = upnp;
            });
        await Task.WhenAll(fetches);
        return result;
    }

    private static async Task SearchOnAsync(
        IPAddress local, TimeSpan listen,
        Dictionary<IPAddress, (string? Location, string? Server, HashSet<string> Targets)> responses,
        CancellationToken cancellationToken)
    {
        UdpClient udp;
        try
        {
            udp = new UdpClient(new IPEndPoint(local, 0));
        }
        catch (SocketException)
        {
            return; // the address went away since the interfaces were read
        }
        using var _ = udp;
        var request = Encoding.ASCII.GetBytes(
            "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: 239.255.255.250:1900\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\n" +
            "ST: ssdp:all\r\n\r\n");
        try
        {
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
            // UDP gets lost; twice is the usual practice.
            await udp.SendAsync(request, Group, cancellationToken);
            await Task.Delay(150, cancellationToken);
            await udp.SendAsync(request, Group, cancellationToken);
        }
        catch (SocketException)
        {
            return;
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(listen);
        try
        {
            while (true)
            {
                var received = await udp.ReceiveAsync(cts.Token);
                var headers = ParseHeaders(Encoding.UTF8.GetString(received.Buffer));
                var from = received.RemoteEndPoint.Address;
                lock (responses)
                {
                    if (!responses.TryGetValue(from, out var entry))
                        entry = (null, null, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                    headers.TryGetValue("LOCATION", out var location);
                    headers.TryGetValue("SERVER", out var server);
                    if (headers.TryGetValue("ST", out var st))
                        entry.Targets.Add(st);
                    // Prefer the root device description.
                    if (entry.Location is null || st == "upnp:rootdevice")
                        entry.Location = location ?? entry.Location;
                    entry.Server ??= server;
                    responses[from] = entry;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }
        catch (SocketException)
        {
        }
    }

    internal static Dictionary<string, string> ParseHeaders(string response)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in response.Split("\r\n").Skip(1))
        {
            int colon = line.IndexOf(':');
            if (colon > 0)
                headers[line[..colon].Trim()] = line[(colon + 1)..].Trim();
        }
        return headers;
    }

    private static async Task<UpnpInfo?> DescribeAsync(
        string? location, IPAddress from, CancellationToken cancellationToken)
    {
        // Only follow a description on the device that answered - a LOCATION
        // pointing elsewhere is not fetched.
        if (location is null || !Uri.TryCreate(location, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttp || !IPAddress.TryParse(uri.Host, out var host) || !host.Equals(from))
            return null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            using var response = await Http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            if (!response.IsSuccessStatusCode || response.Content.Headers.ContentLength > MaxDescription)
                return null;
            // Bytes, not a string: the XML declaration names the charset,
            // and a header with one .NET does not know would throw.
            await using var stream = await response.Content.ReadAsStreamAsync(cts.Token);
            var buffer = new byte[MaxDescription + 1];
            int total = 0, read;
            while (total < buffer.Length && (read = await stream.ReadAsync(buffer.AsMemory(total), cts.Token)) > 0)
                total += read;
            return total > MaxDescription ? null : ParseDescription(new MemoryStream(buffer, 0, total));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Whatever a single device sends, it costs only its description.
            return null;
        }
    }

    internal static UpnpInfo? ParseDescription(string xml) =>
        ParseDescription(new MemoryStream(Encoding.UTF8.GetBytes(xml)));

    internal static UpnpInfo? ParseDescription(Stream xml)
    {
        try
        {
            // No DTDs: the XML comes from any device on the network.
            var settings = new System.Xml.XmlReaderSettings
            {
                DtdProcessing = System.Xml.DtdProcessing.Prohibit,
                XmlResolver = null,
            };
            using var reader = System.Xml.XmlReader.Create(xml, settings);
            var doc = XDocument.Load(reader, LoadOptions.None);
            var device = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
            if (device is null)
                return null;
            string? Get(string name) =>
                device.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim() is { Length: > 0 } v ? v : null;
            return new UpnpInfo(null, Get("friendlyName"), Get("manufacturer"), Get("modelName"),
                Get("modelNumber"), Get("serialNumber"), Get("deviceType"), Array.Empty<string>());
        }
        catch (Exception e) when (e is System.Xml.XmlException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    // GB2312, Shift_JIS, windows-1252 …: older devices declare them.
    static SsdpDiscovery() => Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
}
