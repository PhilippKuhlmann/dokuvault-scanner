using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// NetBIOS node status (UDP 137): the computer name of Windows machines,
/// NAS and many printers that are in no DNS.
/// </summary>
public static class NetBiosResolver
{
    public static async Task<string?> GetNameAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        var request = BuildRequest((ushort)Random.Shared.Next(1, ushort.MaxValue));
        try
        {
            await udp.SendAsync(request, new IPEndPoint(address, 137), cancellationToken);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            var received = await udp.ReceiveAsync(cts.Token);
            return ParseResponse(received.Buffer);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    internal static byte[] BuildRequest(ushort id)
    {
        var packet = new List<byte>
        {
            (byte)(id >> 8), (byte)id,
            0x00, 0x00,       // flags
            0x00, 0x01,       // one question
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20,             // encoded name length
        };
        // "*" padded with NULs to 16 bytes, each nibble + 'A'.
        var name = new byte[16];
        name[0] = (byte)'*';
        foreach (var b in name)
        {
            packet.Add((byte)('A' + (b >> 4)));
            packet.Add((byte)('A' + (b & 0x0F)));
        }
        packet.AddRange(new byte[] { 0x00, 0x00, 0x21, 0x00, 0x01 }); // end, NBSTAT, IN
        return packet.ToArray();
    }

    /// <summary>The unique workstation name (suffix 0x00), else the first unique name.</summary>
    internal static string? ParseResponse(byte[] packet)
    {
        const int namesOffset = 56;
        if (packet.Length < namesOffset + 1)
            return null;
        int count = packet[namesOffset];
        string? fallback = null;
        for (int i = 0; i < count; i++)
        {
            int start = namesOffset + 1 + i * 18;
            if (start + 18 > packet.Length)
                break;
            var name = Encoding.ASCII.GetString(packet, start, 15).TrimEnd(' ', '\0');
            byte suffix = packet[start + 15];
            bool group = (packet[start + 16] & 0x80) != 0;
            if (group || name.Length == 0)
                continue;
            if (suffix == 0x00)
                return name;
            fallback ??= name;
        }
        return fallback;
    }
}
