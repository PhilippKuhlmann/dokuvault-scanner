using System.Net;
using System.Text.Json;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Tests;

public class DhcpRangeTests
{
    [Theory]
    [InlineData("", 0)]
    [InlineData("  ", 0)]
    [InlineData("192.168.1.100-199", 1)]
    [InlineData("192.168.1.100-199, 192.168.1.220-230", 2)]
    [InlineData("192.168.1.100-199;10.0.0.5", 2)]
    [InlineData("192.168.1.100 – 192.168.1.199", 1)]
    public void Reads_lists_of_ranges(string text, int count)
    {
        Assert.True(IpRange.TryParseList(text, out var ranges, out var error), error);
        Assert.Equal(count, ranges.Count);
    }

    [Fact]
    public void A_pool_may_be_larger_than_what_can_be_scanned()
    {
        Assert.False(IpRange.TryParse("10.0.0.0-10.0.255.255", out _, out _));
        Assert.True(IpRange.TryParseList("10.0.0.0-10.0.255.255", out var ranges, out _));
        Assert.Equal(65536, ranges[0].Count);
    }

    [Fact]
    public void Names_the_part_that_is_wrong()
    {
        Assert.False(IpRange.TryParseList("192.168.1.100-199, 192.168.1", out var ranges, out var error));
        Assert.Empty(ranges);
        Assert.Contains("„192.168.1“", error);
    }

    [Theory]
    [InlineData("192.168.1.100-192.168.1.199", "192.168.1.100-199")]
    [InlineData("192.168.1.100-192.168.2.5", "192.168.1.100-192.168.2.5")]
    [InlineData("192.168.1.100", "192.168.1.100")]
    public void Writes_what_it_can_read_back(string text, string expected)
    {
        Assert.True(IpRange.TryParse(text, out var range, out _));
        var input = range!.ToInput();
        Assert.Equal(expected, input);
        Assert.True(IpRange.TryParse(input, out var again, out _));
        Assert.Equal(range.First, again!.First);
        Assert.Equal(range.Last, again.Last);
    }

    [Fact]
    public void Overlaps_at_the_edges_only_when_shared()
    {
        Assert.True(IpRange.TryParse("10.0.0.10-20", out var a, out _));
        Assert.True(IpRange.TryParse("10.0.0.20-30", out var b, out _));
        Assert.True(IpRange.TryParse("10.0.0.21-30", out var c, out _));
        Assert.True(a!.Overlaps(b!));
        Assert.False(a.Overlaps(c!));
    }

    private static ImportRequest Request(int? networkId) => new("acme", "iotdevice",
        new Dictionary<string, object?> { ["site_id"] = "3", ["name"] = "Shelly Flur" },
        IPAddress.Parse("192.168.1.150"), networkId, "MAC 24:0A:C4:00:00:01", Dhcp: true);

    [Fact]
    public async Task Per_dhcp_sends_the_vlan_and_no_address()
    {
        var server = new FakeServer()
            .On("POST /api/mobile/customers/acme/iotdevice", HttpStatusCode.Created, new { type = "iotdevice", id = 7, name = "Shelly Flur" })
            .On("POST /api/mobile/objects/iotdevice/7/ip-addresses", HttpStatusCode.Created,
                new[] { new { id = 1, dhcp = true, address = "DHCP", label = "MAC 24:0A:C4:00:00:01", network = "LAN" } });
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var result = await new DeviceImporter(client).ImportAsync(Request(5), CancellationToken.None);

        Assert.Equal(ImportOutcome.Created, result.Outcome);
        var body = JsonDocument.Parse(server.Requests[1].Body!).RootElement;
        Assert.True(body.GetProperty("dhcp").GetBoolean());
        Assert.Equal(5, body.GetProperty("network_id").GetInt32());
        Assert.False(body.TryGetProperty("address", out _));
    }

    [Fact]
    public async Task Per_dhcp_without_vlan_creates_nothing()
    {
        var server = new FakeServer();
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var result = await new DeviceImporter(client).ImportAsync(Request(null), CancellationToken.None);

        Assert.Equal(ImportOutcome.Failed, result.Outcome);
        Assert.Empty(server.Requests);
    }

    [Theory]
    [InlineData("MAC 24:0A:C4:00:00:01", "24:0A:C4:00:00:01")]
    [InlineData("Flur · mac 24-0a-c4-00-00-01", "24:0A:C4:00:00:01")]
    [InlineData("Flur", null)]
    [InlineData(null, null)]
    public void Finds_the_mac_in_a_label(string? label, string? expected)
    {
        var macs = DokuVaultClient.MacsIn(label).ToList();
        if (expected is null)
            Assert.Empty(macs);
        else
            Assert.Equal(expected, Assert.Single(macs));
    }

    [Fact]
    public async Task Knows_devices_per_dhcp_by_their_mac()
    {
        var server = new FakeServer()
            .On("GET /api/mobile/customers/acme/networks", HttpStatusCode.OK,
                new { entries = new object[] { new { id = 1, name = "LAN", network = "192.168.1.0", cidr = 24 } } })
            .On("GET /api/mobile/customers/acme/networks/1", HttpStatusCode.OK, """
                {"id":1,"name":"LAN","truncated":false,"rows":[
                  {"kind":"dhcp","from":"192.168.1.100","to":"192.168.1.199","gateway":false,"devices":[
                    {"name":"Shelly Flur","type":"iotdevice","id":7,"in_pool":false},
                    {"name":"Fest (192.168.1.150)","type":"server","id":8,"in_pool":true},
                    {"name":"Ohne MAC","type":"iotdevice","id":9,"in_pool":false},
                    {"name":"Nicht sichtbar","type":null,"id":null,"in_pool":false}]}],
                 "dhcp_outside_range":[{"name":"Shelly Flur","type":"iotdevice","id":7,"in_pool":false}]}
                """)
            .On("GET /api/mobile/objects/iotdevice/7", HttpStatusCode.OK,
                new { type = "iotdevice", id = 7, name = "Shelly Flur", ip_addresses = new[] { new { id = 1, dhcp = true, address = "DHCP", label = "MAC 24:0A:C4:00:00:01" } } })
            .On("GET /api/mobile/objects/iotdevice/9", HttpStatusCode.OK,
                new { type = "iotdevice", id = 9, name = "Ohne MAC", ip_addresses = new[] { new { id = 2, dhcp = true, address = "DHCP", label = "Flur" } } });
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var plans = await client.DocumentedAddressesAsync("acme", CancellationToken.None);

        var device = Assert.Single(plans.DhcpDevices);
        Assert.Equal("24:0A:C4:00:00:01", device.Mac);
        Assert.Equal(7, device.Id);
        // Asked once, though listed twice; the fixed address in the pool stays out.
        Assert.Single(server.Requests, r => r.Path.EndsWith("/objects/iotdevice/7"));
        Assert.DoesNotContain(server.Requests, r => r.Path.EndsWith("/objects/server/8"));
        // Not silently: two devices cannot be told again.
        Assert.Contains(plans.Warnings, w => w.StartsWith("2 per DHCP"));
    }

    [Fact]
    public async Task Reads_the_pools_documented_at_the_vlans()
    {
        var server = new FakeServer()
            .On("GET /api/mobile/customers/acme/networks", HttpStatusCode.OK, new
            {
                entries = new object[]
                {
                    new { id = 1, name = "LAN", network = "192.168.1.0", cidr = 24, site = new { id = 7, name = "HH" } },
                    new { id = 2, name = "Ohne", network = "192.168.2.0", cidr = 24 },
                    new { id = 3, name = "Verdreht", network = "192.168.3.0", cidr = 24 },
                    new { id = 4, name = "Kaputt", network = "192.168.4.0", cidr = 24 },
                },
            })
            .On("GET /api/mobile/customers/acme/networks/1", HttpStatusCode.OK,
                new { id = 1, name = "LAN", dhcp_start = "192.168.1.100", dhcp_end = "192.168.1.199", truncated = false, rows = Array.Empty<object>() })
            .On("GET /api/mobile/customers/acme/networks/2", HttpStatusCode.OK,
                new { id = 2, name = "Ohne", dhcp_start = (string?)null, dhcp_end = (string?)null, truncated = false, rows = Array.Empty<object>() })
            .On("GET /api/mobile/customers/acme/networks/3", HttpStatusCode.OK,
                new { id = 3, name = "Verdreht", dhcp_start = "192.168.3.50", dhcp_end = "192.168.3.10", truncated = false, rows = Array.Empty<object>() })
            .On("GET /api/mobile/customers/acme/networks/4", HttpStatusCode.OK,
                new { id = 4, name = "Kaputt", dhcp_start = "egal", dhcp_end = "192.168.4.10", truncated = false, rows = Array.Empty<object>() });
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var plans = await client.DocumentedAddressesAsync("acme", CancellationToken.None);

        var pool = Assert.Single(plans.DhcpPools);
        Assert.Equal("LAN", pool.NetworkName);
        Assert.Equal(7, pool.SiteId);
        Assert.Equal("192.168.1.100-199", pool.Range.ToInput());
        Assert.True(pool.Range.Contains(IPAddress.Parse("192.168.1.150")));
        Assert.False(pool.Range.Contains(IPAddress.Parse("192.168.1.200")));
    }
}
