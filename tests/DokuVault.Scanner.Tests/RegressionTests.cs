using System.Net;
using System.Text;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Tests;

/// <summary>Cases found in review: each one used to crash, hang or mislead.</summary>
public class RegressionTests
{
    [Fact]
    public void Snmp_length_near_int_max_is_rejected_not_thrown()
    {
        // 30 84 7F FF FF FF: a SEQUENCE claiming 2 GB.
        var packet = new byte[] { 0x30, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x01 };
        Assert.Null(SnmpClient.ParseResponse(packet, 1));
    }

    [Theory]
    [InlineData("0x0A.0.0.1")]
    [InlineData("192.168.1.256")]
    [InlineData("+1.2.3.4")]
    [InlineData("1.2.3.4 5")]
    public void Non_decimal_octets_are_refused(string text) =>
        Assert.False(IpRange.TryParseV4(text, out _));

    [Fact]
    public void Leading_zeros_are_decimal_not_octal()
    {
        // IPAddress.TryParse reads "010" as octal 8.
        Assert.True(IpRange.TryParseV4("192.168.010.1", out var address));
        Assert.Equal("192.168.10.1", address.ToString());
    }

    [Theory]
    [InlineData("Spring Technologies", null)]
    [InlineData("Ring LLC", "Ring")]
    [InlineData("Philips Hue Bridge", "hue")]
    [InlineData("esp-garage-tor", "esp-")]
    public void Words_match_only_at_word_start(string text, string? expected) =>
        Assert.Equal(expected, DeviceClassifier.Matches(text, new[] { "Ring", "hue", "esp-" }));

    [Fact]
    public void Upnp_description_in_a_legacy_charset_is_read()
    {
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var xml = "<?xml version=\"1.0\" encoding=\"windows-1252\"?><root><device><friendlyName>Kühlschrank</friendlyName></device></root>";
        var bytes = Encoding.GetEncoding(1252).GetBytes(xml);
        var info = SsdpDiscovery.ParseDescription(new MemoryStream(bytes));
        Assert.Equal("Kühlschrank", info!.FriendlyName);
    }

    [Fact]
    public void Mdns_pointer_loop_does_not_hang_or_throw()
    {
        // A response whose single answer name points at itself.
        var packet = new byte[] { 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 1, 0, 2, 0xC0, 12 };
        var services = MdnsBrowser.ParseResponse(packet, out _);
        Assert.Empty(services);
    }

    [Fact]
    public void Mdns_merge_keeps_snapshots_immutable()
    {
        var d = new ScannedDevice { Address = IPAddress.Parse("10.0.0.5") };
        d.AddMdns(new MdnsService("_hap._tcp.local", "Lampe", new Dictionary<string, string>()));
        var before = d.Mdns;
        d.AddMdns(new MdnsService("_hap._tcp.local", "Lampe", new Dictionary<string, string>()));
        d.AddMdns(new MdnsService("_hue._tcp.local", "Bridge", new Dictionary<string, string>()));
        Assert.Single(before);
        Assert.Equal(2, d.Mdns.Count);
    }

    [Fact]
    public async Task One_unreadable_ip_plan_costs_only_that_vlan()
    {
        var server = new FakeServer()
            .On("GET /api/mobile/customers/acme/networks", HttpStatusCode.OK, new
            {
                entries = new object[]
                {
                    new { id = 1, name = "LAN", network = "192.168.1.0", cidr = 24 },
                    new { id = 2, name = "Gast", network = "192.168.2.0", cidr = 24 },
                    new { id = 3, name = "Groß", network = "10.0.0.0", cidr = 16 },
                },
            })
            .On("GET /api/mobile/customers/acme/networks/1", HttpStatusCode.OK,
                "{\"id\":1,\"name\":\"LAN\",\"truncated\":false,\"rows\":[{\"kind\":\"device\",\"from\":\"192.168.1.9\",\"to\":\"192.168.1.9\",\"gateway\":false,\"devices\":[{\"name\":\"Drucker\",\"type\":\"printer\",\"id\":4,\"in_pool\":false}]}]}")
            .On("GET /api/mobile/customers/acme/networks/2", HttpStatusCode.InternalServerError, "{}")
            .On("GET /api/mobile/customers/acme/networks/3", HttpStatusCode.OK,
                "{\"id\":3,\"name\":\"Groß\",\"truncated\":true,\"rows\":[]}");
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var plans = await client.DocumentedAddressesAsync("acme", CancellationToken.None);

        Assert.Single(plans.Addresses);
        Assert.Equal(3, plans.Networks.Count);
        Assert.Equal(new[] { 1 }, plans.Covered.Select(n => n.Id));
        Assert.Equal(2, plans.Warnings.Count);
    }
}
