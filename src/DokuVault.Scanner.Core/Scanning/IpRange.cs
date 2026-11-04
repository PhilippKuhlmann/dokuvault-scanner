using System.Net;
using System.Net.Sockets;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// A contiguous IPv4 range. Built from CIDR ("192.168.1.0/24"), a span
/// ("192.168.1.10-192.168.1.50" or "192.168.1.10-50") or a single address.
/// </summary>
public sealed class IpRange
{
    /// <summary>Above this the scan would take long and flood the network: /20.</summary>
    public const int MaxHosts = 4096;

    public uint First { get; }
    public uint Last { get; }

    /// <summary>Set when the range came from CIDR - used to assign VLANs.</summary>
    public int? PrefixLength { get; }

    public IpRange(uint first, uint last, int? prefixLength = null)
    {
        if (last < first)
            throw new ArgumentException("Das Ende des Bereichs liegt vor dem Anfang.");
        First = first;
        Last = last;
        PrefixLength = prefixLength;
    }

    public long Count => (long)Last - First + 1;

    public IEnumerable<IPAddress> Addresses()
    {
        for (long i = First; i <= Last; i++)
            yield return ToAddress((uint)i);
    }

    public bool Contains(IPAddress address) =>
        address.AddressFamily == AddressFamily.InterNetwork && ToUInt(address) is var v && v >= First && v <= Last;

    public override string ToString() =>
        PrefixLength is int p
            ? $"{ToAddress(NetworkOf(First, p))}/{p}"
            : First == Last ? ToAddress(First).ToString() : $"{ToAddress(First)} – {ToAddress(Last)}";

    /// <summary>
    /// The hosts of a subnet: without network and broadcast address,
    /// except for /31 and /32, which have none.
    /// </summary>
    public static IpRange FromCidr(IPAddress address, int prefixLength)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Nur IPv4-Adressen werden unterstützt.");
        if (prefixLength is < 0 or > 32)
            throw new ArgumentException("Die Präfixlänge muss zwischen 0 und 32 liegen.");

        uint network = NetworkOf(ToUInt(address), prefixLength);
        uint broadcast = network | ~MaskOf(prefixLength);
        if (prefixLength >= 31)
            return new IpRange(network, broadcast, prefixLength);
        return new IpRange(network + 1, broadcast - 1, prefixLength);
    }

    public bool Overlaps(IpRange other) => First <= other.Last && other.First <= Last;

    /// <summary>As typed into a field: "192.168.1.100-199", which TryParse reads back.</summary>
    public string ToInput()
    {
        if (First == Last)
            return ToAddress(First).ToString();
        return (First >> 8) == (Last >> 8)
            ? $"{ToAddress(First)}-{Last & 0xFF}"
            : $"{ToAddress(First)}-{ToAddress(Last)}";
    }

    /// <summary>
    /// Several ranges separated by comma or semicolon; empty means none. No
    /// size limit: these are only compared against, never scanned.
    /// </summary>
    public static bool TryParseList(string? text, out IReadOnlyList<IpRange> ranges, out string? error)
    {
        ranges = Array.Empty<IpRange>();
        error = null;
        var result = new List<IpRange>();
        foreach (var part in (text ?? "").Split(',', ';'))
        {
            if (string.IsNullOrWhiteSpace(part))
                continue;
            if (!TryParse(part, out var range, out var partError, long.MaxValue))
            {
                error = $"„{part.Trim()}“: {partError}";
                return false;
            }
            result.Add(range!);
        }
        ranges = result;
        return true;
    }

    public static bool TryParse(string? text, out IpRange? range, out string? error) =>
        TryParse(text, out range, out error, MaxHosts);

    private static bool TryParse(string? text, out IpRange? range, out string? error, long maxHosts)
    {
        range = null;
        error = null;
        text = text?.Trim().Replace('–', '-');
        if (string.IsNullOrEmpty(text))
        {
            error = "Bitte einen Bereich eingeben, z. B. 192.168.1.0/24.";
            return false;
        }

        try
        {
            int slash = text.IndexOf('/');
            int dash = text.IndexOf('-');
            if (slash > 0)
            {
                if (!TryParseV4(text[..slash], out var address) || !int.TryParse(text[(slash + 1)..].Trim(), out int prefix))
                {
                    error = "Ungültige CIDR-Angabe.";
                    return false;
                }
                range = FromCidr(address, prefix);
            }
            else if (dash > 0)
            {
                string left = text[..dash].Trim();
                string right = text[(dash + 1)..].Trim();
                if (!TryParseV4(left, out var from))
                {
                    error = "Ungültige Anfangsadresse.";
                    return false;
                }
                IPAddress? to;
                // "192.168.1.10-50": the last octet only.
                if (!right.Contains('.') && byte.TryParse(right, out byte lastOctet))
                {
                    var bytes = from.GetAddressBytes();
                    bytes[3] = lastOctet;
                    to = new IPAddress(bytes);
                }
                else if (!TryParseV4(right, out to))
                {
                    error = "Ungültige Endadresse.";
                    return false;
                }
                range = new IpRange(ToUInt(from), ToUInt(to!));
            }
            else
            {
                if (!TryParseV4(text, out var single))
                {
                    error = "Ungültige IP-Adresse.";
                    return false;
                }
                range = new IpRange(ToUInt(single), ToUInt(single));
            }
        }
        catch (ArgumentException e)
        {
            error = e.Message;
            return false;
        }

        if (range.Count > maxHosts)
        {
            error = $"Der Bereich umfasst {range.Count:N0} Adressen – höchstens {maxHosts:N0} sind erlaubt (/20).";
            range = null;
            return false;
        }
        return true;
    }

    /// <summary>
    /// Strict dotted quad of decimal octets. IPAddress.TryParse would also
    /// take "10", "10.1", octal "010" and hex "0x0A" - "192.168.010.1" would
    /// then be scanned as 192.168.8.1.
    /// </summary>
    public static bool TryParseV4(string text, out IPAddress address)
    {
        address = IPAddress.None;
        var parts = text.Trim().Split('.');
        if (parts.Length != 4)
            return false;
        var bytes = new byte[4];
        for (int i = 0; i < 4; i++)
        {
            if (parts[i].Length is 0 or > 3 || !parts[i].All(char.IsAsciiDigit) ||
                !byte.TryParse(parts[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out bytes[i]))
                return false;
        }
        address = new IPAddress(bytes);
        return true;
    }

    public static uint ToUInt(IPAddress address)
    {
        var b = address.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }

    public static IPAddress ToAddress(uint value) =>
        new(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

    public static uint MaskOf(int prefixLength) =>
        prefixLength == 0 ? 0u : uint.MaxValue << (32 - prefixLength);

    public static uint NetworkOf(uint address, int prefixLength) => address & MaskOf(prefixLength);

    public static int PrefixFromMask(IPAddress mask)
    {
        uint m = ToUInt(mask);
        int bits = 0;
        while ((m & 0x80000000) != 0)
        {
            bits++;
            m <<= 1;
        }
        return bits;
    }
}
