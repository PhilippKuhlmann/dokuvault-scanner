using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>One service a device announces over mDNS/DNS-SD.</summary>
public sealed record MdnsService(string ServiceType, string InstanceName, IReadOnlyDictionary<string, string> Txt);

/// <summary>
/// Asks the LAN once over multicast DNS which devices offer printing,
/// HomeKit, Cast, Shelly, ESPHome and the like. The query goes from an
/// ephemeral port, so responders answer us directly (RFC 6762, 6.7 "legacy
/// unicast") - no need to bind 5353, which Windows itself holds.
/// </summary>
public static class MdnsBrowser
{
    public static readonly string[] ServiceTypes =
    {
        "_ipp._tcp.local", "_ipps._tcp.local", "_printer._tcp.local", "_pdl-datastream._tcp.local",
        "_scanner._tcp.local", "_uscan._tcp.local",
        "_hap._tcp.local", "_homekit._tcp.local", "_matter._tcp.local", "_matterc._udp.local",
        "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_spotify-connect._tcp.local",
        "_shelly._tcp.local", "_esphomelib._tcp.local", "_hue._tcp.local", "_mqtt._tcp.local",
        "_sonos._tcp.local", "_amzn-wplay._tcp.local", "_miio._udp.local", "_axis-video._tcp.local",
        "_http._tcp.local",
    };

    private static readonly IPEndPoint Group = new(IPAddress.Parse("224.0.0.251"), 5353);

    /// <summary>Services by the IPv4 address that announced them.</summary>
    public static async Task<Dictionary<IPAddress, List<MdnsService>>> BrowseAsync(
        IEnumerable<IPAddress> localAddresses, TimeSpan listen, CancellationToken cancellationToken)
    {
        var found = new Dictionary<IPAddress, List<MdnsService>>();
        var tasks = localAddresses.Select(a => BrowseOnAsync(a, listen, found, cancellationToken)).ToList();
        await Task.WhenAll(tasks);
        return found;
    }

    private static async Task BrowseOnAsync(
        IPAddress local, TimeSpan listen, Dictionary<IPAddress, List<MdnsService>> found,
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
        try
        {
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes());
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
            // Several small queries rather than one: some responders ignore
            // queries with many questions.
            foreach (var chunk in ServiceTypes.Chunk(6))
                await udp.SendAsync(BuildQuery(chunk), Group, cancellationToken);
        }
        catch (SocketException)
        {
            return; // interface without multicast
        }

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(listen);
        try
        {
            while (true)
            {
                var received = await udp.ReceiveAsync(cts.Token);
                var services = ParseResponse(received.Buffer, out var addresses);
                if (services.Count == 0)
                    continue;
                // Normally the device answers for itself. A sleep proxy answers
                // for others - then the single A record names the device.
                var sender = received.RemoteEndPoint.Address;
                var owner = addresses.Count == 1 && !addresses.Contains(sender) ? addresses[0] : sender;
                lock (found)
                {
                    if (!found.TryGetValue(owner, out var list))
                        found[owner] = list = new List<MdnsService>();
                    foreach (var service in services)
                        if (!list.Any(s => s.ServiceType == service.ServiceType && s.InstanceName == service.InstanceName))
                            list.Add(service);
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

    internal static byte[] BuildQuery(IEnumerable<string> names)
    {
        var questions = names.ToList();
        var packet = new List<byte>
        {
            0, 0,             // id
            0, 0,             // flags: standard query
            (byte)(questions.Count >> 8), (byte)questions.Count,
            0, 0, 0, 0, 0, 0, // answers, authority, additional
        };
        foreach (var name in questions)
        {
            packet.AddRange(EncodeName(name));
            packet.AddRange(new byte[] { 0, 12 });      // PTR
            packet.AddRange(new byte[] { 0x80, 1 });    // QU bit + IN: ask for unicast reply
        }
        return packet.ToArray();
    }

    private static IEnumerable<byte> EncodeName(string name)
    {
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.UTF8.GetBytes(label);
            yield return (byte)bytes.Length;
            foreach (var b in bytes)
                yield return b;
        }
        yield return 0;
    }

    private sealed record Record(string Name, ushort Type, byte[] Packet, int DataOffset, int DataLength);

    /// <summary>The services in one response, and the IPv4 addresses it carries in A records.</summary>
    internal static List<MdnsService> ParseResponse(byte[] packet, out List<IPAddress> addresses)
    {
        addresses = new List<IPAddress>();
        var services = new List<MdnsService>();
        if (packet.Length < 12 || (packet[2] & 0x80) == 0)
            return services; // not a response

        int questions = (packet[4] << 8) | packet[5];
        int records = ((packet[6] << 8) | packet[7]) + ((packet[8] << 8) | packet[9]) + ((packet[10] << 8) | packet[11]);
        int pos = 12;
        try
        {
            for (int i = 0; i < questions; i++)
            {
                ReadName(packet, ref pos);
                pos += 4;
            }

            var all = new List<Record>();
            for (int i = 0; i < records && pos < packet.Length; i++)
            {
                var name = ReadName(packet, ref pos);
                ushort type = (ushort)((packet[pos] << 8) | packet[pos + 1]);
                int length = (packet[pos + 8] << 8) | packet[pos + 9];
                pos += 10;
                if (pos + length > packet.Length)
                    break;
                all.Add(new Record(name, type, packet, pos, length));
                pos += length;
            }

            foreach (var a in all.Where(r => r.Type == 1 && r.DataLength == 4))
            {
                var address = new IPAddress(packet.AsSpan(a.DataOffset, 4));
                if (!addresses.Contains(address))
                    addresses.Add(address);
            }

            foreach (var ptr in all.Where(r => r.Type == 12))
            {
                int p = ptr.DataOffset;
                var instance = ReadName(packet, ref p);
                var serviceType = ptr.Name.ToLowerInvariant();
                if (serviceType == "_services._dns-sd._udp.local")
                    continue;
                var txt = all.FirstOrDefault(r => r.Type == 16 && string.Equals(r.Name, instance, StringComparison.OrdinalIgnoreCase));
                var label = instance.EndsWith("." + ptr.Name, StringComparison.OrdinalIgnoreCase)
                    ? instance[..^(ptr.Name.Length + 1)]
                    : instance;
                services.Add(new MdnsService(serviceType, label, txt is null ? new Dictionary<string, string>() : ParseTxt(txt)));
            }
        }
        catch (IndexOutOfRangeException)
        {
            // truncated packet - keep what was read
        }
        catch (ArgumentOutOfRangeException)
        {
        }
        return services;
    }

    private static Dictionary<string, string> ParseTxt(Record txt)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int pos = txt.DataOffset;
        int end = txt.DataOffset + txt.DataLength;
        while (pos < end)
        {
            int length = txt.Packet[pos++];
            if (pos + length > end)
                break;
            var entry = Encoding.UTF8.GetString(txt.Packet, pos, length);
            pos += length;
            int eq = entry.IndexOf('=');
            if (eq > 0)
                result[entry[..eq]] = entry[(eq + 1)..];
            else if (entry.Length > 0)
                result[entry] = "";
        }
        return result;
    }

    /// <summary>A DNS name with compression pointers; pos moves past it.</summary>
    internal static string ReadName(byte[] packet, ref int pos)
    {
        var labels = new List<string>();
        int jumps = 0;
        int cursor = pos;
        bool jumped = false;
        while (true)
        {
            int length = packet[cursor];
            if (length == 0)
            {
                cursor++;
                break;
            }
            if ((length & 0xC0) == 0xC0)
            {
                int target = ((length & 0x3F) << 8) | packet[cursor + 1];
                if (!jumped)
                    pos = cursor + 2;
                jumped = true;
                cursor = target;
                if (++jumps > 20)
                    throw new IndexOutOfRangeException("DNS name loop");
                continue;
            }
            labels.Add(Encoding.UTF8.GetString(packet, cursor + 1, length));
            cursor += 1 + length;
        }
        if (!jumped)
            pos = cursor;
        return string.Join(".", labels);
    }
}
