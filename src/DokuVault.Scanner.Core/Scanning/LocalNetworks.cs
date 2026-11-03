using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>An IPv4 network this computer sits in, as offered in the scan dropdown.</summary>
public sealed record LocalNetwork(
    string InterfaceName,
    string InterfaceDescription,
    IPAddress LocalAddress,
    int PrefixLength,
    IPAddress? Gateway)
{
    public IpRange Range => IpRange.FromCidr(LocalAddress, PrefixLength);

    /// <summary>
    /// The range offered for a scan: the subnet, or for anything larger
    /// than /20 the /24 around the own address - nobody wants to ping a /16.
    /// </summary>
    public IpRange SuggestedRange =>
        PrefixLength >= 20 ? Range : IpRange.FromCidr(LocalAddress, 24);

    public string Display =>
        $"{SuggestedRange}  ·  {InterfaceName} ({LocalAddress})";

    public override string ToString() => Display;
}

public static class LocalNetworks
{
    public static IReadOnlyList<LocalNetwork> Discover()
    {
        var result = new List<LocalNetwork>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up ||
                nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                continue;

            IPInterfaceProperties props;
            try
            {
                props = nic.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));

            foreach (var unicast in props.UnicastAddresses)
            {
                var address = unicast.Address;
                if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address))
                    continue;
                // APIPA: no DHCP answer, nothing worth scanning.
                if (address.GetAddressBytes() is [169, 254, ..])
                    continue;

                int prefix = unicast.PrefixLength > 0
                    ? unicast.PrefixLength
                    : IpRange.PrefixFromMask(unicast.IPv4Mask);
                if (prefix is <= 0 or > 32)
                    continue;

                result.Add(new LocalNetwork(nic.Name, nic.Description, address, prefix, gateway));
            }
        }

        // Interfaces with a gateway first: that is the LAN, not a Hyper-V switch.
        return result
            .OrderByDescending(n => n.Gateway is not null)
            .ThenBy(n => n.InterfaceName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
