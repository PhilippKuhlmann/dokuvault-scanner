using System.Net;
using System.Runtime.InteropServices;

namespace DokuVault.Scanner.Core.Scanning;

public enum NeighborState
{
    Unreachable = 0,
    Incomplete = 1,
    Probe = 2,
    Delay = 3,
    Stale = 4,
    Reachable = 5,
    Permanent = 6,
}

public sealed record Neighbor(IPAddress Address, string Mac, NeighborState State);

/// <summary>
/// The Windows neighbour (ARP) cache via GetIpNetTable2. Before every ping
/// Windows asks by ARP who holds the address - so after a ping sweep the
/// cache knows every device in the own subnet that answered ARP, including
/// those whose firewall swallows the ping.
/// </summary>
public static class NeighborTable
{
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int GetIpNetTable2(ushort family, out IntPtr table);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern void FreeMibTable(IntPtr memory);

    private const ushort AfInet = 2;

    // MIB_IPNET_ROW2 (netioapi.h), x64 and x86 alike:
    //   SOCKADDR_INET Address        0  (28)
    //   NET_IFINDEX   InterfaceIndex 28 (4)
    //   NET_LUID      InterfaceLuid  32 (8)
    //   UCHAR         PhysicalAddress[32] 40
    //   ULONG         PhysicalAddressLength 72
    //   NL_NEIGHBOR_STATE State      76
    //   UCHAR flags + union          80 .. 88
    private const int RowSize = 88;
    private const int TableOffset = 8; // ULONG NumEntries, padded to the row's 8-byte alignment

    public static IReadOnlyList<Neighbor> Read()
    {
        var result = new List<Neighbor>();
        if (!OperatingSystem.IsWindows())
            return result;
        if (GetIpNetTable2(AfInet, out var table) != 0 || table == IntPtr.Zero)
            return result;
        try
        {
            int count = Marshal.ReadInt32(table);
            for (int i = 0; i < count; i++)
            {
                var row = table + TableOffset + i * RowSize;
                if ((ushort)Marshal.ReadInt16(row) != AfInet)
                    continue;
                var addressBytes = new byte[4];
                Marshal.Copy(row + 4, addressBytes, 0, 4);
                int length = Marshal.ReadInt32(row + 72);
                var state = (NeighborState)Marshal.ReadInt32(row + 76);
                if (length != 6)
                    continue;
                var mac = new byte[6];
                Marshal.Copy(row + 40, mac, 0, 6);
                if (mac.All(b => b == 0) || mac.All(b => b == 0xFF))
                    continue;
                // Multicast neighbours (01:00:5E…) are no devices.
                if ((mac[0] & 0x01) != 0)
                    continue;
                result.Add(new Neighbor(new IPAddress(addressBytes), ArpResolver.Format(mac), state));
            }
        }
        finally
        {
            FreeMibTable(table);
        }
        return result;
    }
}
