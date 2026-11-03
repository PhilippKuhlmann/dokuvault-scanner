using System.Net;
using System.Runtime.InteropServices;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// Resolves the MAC address of a host in the own subnet with an ARP request
/// (iphlpapi SendARP). A host that answers ARP is alive even when its
/// firewall drops ping - most IoT devices and printers in a LAN are found
/// this way. Outside the own subnet ARP gives nothing (the router answers
/// for them, and SendARP refuses).
/// </summary>
public static class ArpResolver
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLen);

    private const int NoError = 0;

    /// <summary>The MAC, or null when nobody answered. Blocks up to about one second.</summary>
    public static string? Resolve(IPAddress address)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var mac = new byte[6];
        int length = mac.Length;
        // SendARP wants the address in network byte order, which is the
        // byte order of GetAddressBytes read as a little-endian uint.
        uint dest = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        int status = SendARP(dest, 0, mac, ref length);
        if (status != NoError || length != 6 || mac.All(b => b == 0))
            return null;
        return Format(mac);
    }

    public static Task<string?> ResolveAsync(IPAddress address, CancellationToken cancellationToken) =>
        Task.Run(() => Resolve(address), cancellationToken);

    public static string Format(ReadOnlySpan<byte> mac) =>
        string.Join(":", mac.ToArray().Select(b => b.ToString("X2")));

    /// <summary>
    /// "Locally administered" bit: a randomised MAC (private Wi-Fi address
    /// on phones, laptops) - no manufacturer to look up.
    /// </summary>
    public static bool IsRandomized(string mac) =>
        TryParse(mac, out var bytes) && (bytes[0] & 0x02) != 0 && Hypervisor(mac) is null;

    // Prefixes hypervisors give their virtual NICs. QEMU's 52:54:00 has the
    // "locally administered" bit set, but is no phone with a private address.
    private static readonly (string Prefix, string Name)[] VirtualPrefixes =
    {
        ("005056", "VMware"), ("000C29", "VMware"), ("000569", "VMware"), ("001C14", "VMware"),
        ("00155D", "Hyper-V"), ("BC2411", "Proxmox"), ("525400", "QEMU/KVM"), ("080027", "VirtualBox"),
        ("00163E", "Xen"),
    };

    /// <summary>The hypervisor whose virtual NIC this MAC is, or null.</summary>
    public static string? Hypervisor(string? mac)
    {
        if (!TryParse(mac, out var bytes))
            return null;
        var prefix = Convert.ToHexString(bytes, 0, 3);
        return VirtualPrefixes.FirstOrDefault(v => v.Prefix == prefix).Name;
    }

    public static bool TryParse(string? text, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(text))
            return false;
        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12)
            return false;
        bytes = Convert.FromHexString(hex);
        return true;
    }
}
