using System.Net;
using System.Text;
using System.Text.Json;
using DokuVault.Scanner.Core.Api;

namespace DokuVault.Scanner.Tests;

/// <summary>A fake DokuVault: answers by "METHOD path" and records every request.</summary>
internal sealed class FakeServer : HttpMessageHandler
{
    public List<(HttpMethod Method, string Path, string? Body, string? Auth)> Requests { get; } = new();
    public Dictionary<string, Queue<(HttpStatusCode Status, string Body)>> Routes { get; } = new();

    public FakeServer On(string route, HttpStatusCode status, object body)
    {
        if (!Routes.TryGetValue(route, out var queue))
            Routes[route] = queue = new Queue<(HttpStatusCode, string)>();
        queue.Enqueue((status, body as string ?? JsonSerializer.Serialize(body)));
        return this;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.PathAndQuery;
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method, path, body, request.Headers.Authorization?.ToString()));
        Assert.Contains("application/json", request.Headers.Accept.ToString());

        var key = $"{request.Method} {path}";
        if (!Routes.TryGetValue(key, out var queue) || queue.Count == 0)
            return new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{\"message\":\"no route " + key + "\"}") };
        var (status, text) = queue.Count > 1 ? queue.Dequeue() : queue.Peek();
        return new HttpResponseMessage(status) { Content = new StringContent(text, Encoding.UTF8, "application/json") };
    }
}

public class ClientTests
{
    private static (DokuVaultClient Client, FakeServer Server) Make(string? token = "1|abc")
    {
        var server = new FakeServer();
        return (new DokuVaultClient(new Uri("https://doku.example.com"), token, server), server);
    }

    [Theory]
    [InlineData("doku.example.com", "https://doku.example.com/")]
    [InlineData("https://doku.example.com/api/mobile/", "https://doku.example.com/")]
    [InlineData("https://example.com/dokuvault", "https://example.com/dokuvault/")]
    [InlineData("http://dokuvault.test", "http://dokuvault.test/")]
    public void Normalizes_server_url(string input, string expected)
    {
        Assert.True(DokuVaultClient.TryParseServerUrl(input, out var url, out var error), error);
        Assert.Equal(expected, url!.ToString());
    }

    [Fact]
    public void Refuses_plain_http_to_a_real_host()
    {
        Assert.False(DokuVaultClient.TryParseServerUrl("http://doku.example.com", out _, out var error));
        Assert.Contains("https", error);
    }

    [Fact]
    public async Task Login_with_second_factor()
    {
        var (client, server) = Make(token: null);
        server.On("POST /api/mobile/login", HttpStatusCode.OK, new { two_factor = true, challenge = "ch1" })
              .On("POST /api/mobile/login/two-factor", HttpStatusCode.UnprocessableEntity,
                  new { message = "Der Code stimmt nicht.", errors = new { code = new[] { "Der Code stimmt nicht." } } })
              .On("POST /api/mobile/login/two-factor", HttpStatusCode.OK,
                  new { token = "5|tok", expires_at = "2026-12-03T12:00:00+01:00", user = new { name = "Philipp", username = "philipp", customer = (object?)null } });

        var first = await client.LoginAsync("philipp", "geheim", "Scanner PC1", CancellationToken.None);
        Assert.True(first.TwoFactor);
        Assert.False(client.IsSignedIn);
        var login = JsonDocument.Parse(server.Requests[0].Body!).RootElement;
        Assert.Equal("philipp", login.GetProperty("username").GetString());
        Assert.Equal("Scanner PC1", login.GetProperty("device").GetString());

        var wrong = await Assert.ThrowsAsync<DokuVaultApiException>(() => client.LoginTwoFactorAsync("ch1", "000000", CancellationToken.None));
        Assert.Equal("Der Code stimmt nicht.", wrong.Message);
        Assert.True(wrong.FieldErrors.ContainsKey("code"));

        var ok = await client.LoginTwoFactorAsync("ch1", " 123456 ", CancellationToken.None);
        Assert.Equal("5|tok", ok.Token);
        Assert.True(client.IsSignedIn);
        Assert.Equal("123456", JsonDocument.Parse(server.Requests[^1].Body!).RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task Create_keeps_form_field_names_exactly()
    {
        var (client, server) = Make();
        server.On("POST /api/mobile/customers/acme/printer", HttpStatusCode.Created,
            new { type = "printer", id = 42, name = "HP 2.OG", ip_addresses = Array.Empty<object>() });

        var created = await client.CreateObjectAsync("acme", "printer", new Dictionary<string, object?>
        {
            ["site_id"] = "3",
            ["name"] = "HP 2.OG",
            ["serialNumber"] = "VNB3K12345",
        }, CancellationToken.None);

        Assert.Equal(42, created.Id);
        var body = JsonDocument.Parse(server.Requests[0].Body!).RootElement;
        Assert.Equal("VNB3K12345", body.GetProperty("serialNumber").GetString());
        Assert.False(body.TryGetProperty("serial_number", out _));
        Assert.Equal("Bearer 1|abc", server.Requests[0].Auth);
    }

    [Fact]
    public async Task Unauthorized_is_reported_as_such()
    {
        var (client, server) = Make();
        server.On("GET /api/mobile/customers", HttpStatusCode.Unauthorized, new { message = "Unauthenticated." });
        var e = await Assert.ThrowsAsync<DokuVaultApiException>(() => client.CustomersAsync(CancellationToken.None));
        Assert.True(e.IsUnauthorized);
    }

    [Fact]
    public async Task Unreadable_answer_says_so()
    {
        var (client, server) = Make();
        server.On("GET /api/mobile/customers", HttpStatusCode.OK, "<html>Login</html>");
        var e = await Assert.ThrowsAsync<DokuVaultApiException>(() => client.CustomersAsync(CancellationToken.None));
        Assert.Contains("unlesbar", e.Message);
    }

    [Fact]
    public void Plan_addresses_skip_bare_gateway_and_read_pool_devices()
    {
        var detail = JsonSerializer.Deserialize<NetworkDetail>("""
            {"id":5,"name":"LAN · VLAN 1","truncated":false,"rows":[
              {"kind":"device","from":"192.168.1.1","to":"192.168.1.1","gateway":true,"devices":[]},
              {"kind":"device","from":"192.168.1.20","to":"192.168.1.20","gateway":false,"devices":[{"name":"HP 2.OG","type":"printer","id":42,"in_pool":false}]},
              {"kind":"free","from":"192.168.1.21","to":"192.168.1.99","gateway":false,"devices":[]},
              {"kind":"dhcp","from":"192.168.1.100","to":"192.168.1.200","gateway":false,"devices":[{"name":"Shelly Flur (192.168.1.150)","type":"iotdevice","id":7,"in_pool":true}]}
            ]}
            """)!;
        var addresses = DokuVaultClient.PlanAddresses(detail).ToList();
        Assert.Equal(2, addresses.Count);
        Assert.Equal("HP 2.OG", addresses.Single(a => a.Address == "192.168.1.20").Name);
        var pool = addresses.Single(a => a.Address == "192.168.1.150");
        Assert.Equal("Shelly Flur", pool.Name);
        Assert.Equal(5, pool.NetworkId);
    }

    [Fact]
    public void Matches_vlan_by_subnet_and_prefers_site()
    {
        var networks = new List<NetworkEntry>
        {
            new(1, "Gast", "192.168.0.0", "255.255.0.0", null, null, new NetworkSite(1, "Hamburg"), null),
            new(2, "LAN HH", "192.168.1.0", null, 24, null, new NetworkSite(1, "Hamburg"), null),
            new(3, "LAN B", "192.168.1.0", null, 24, null, new NetworkSite(2, "Berlin"), null),
            new(4, "Kaputt", "x", null, 24, null, null, "Netz unlesbar"),
        };
        var ip = IPAddress.Parse("192.168.1.50");
        Assert.Equal(3, DokuVaultClient.MatchNetwork(networks, ip, siteId: 2)!.Id);
        Assert.Equal(2, DokuVaultClient.MatchNetwork(networks, ip, siteId: 1)!.Id);
        Assert.Equal(2, DokuVaultClient.MatchNetwork(networks, ip, siteId: null)!.Id);
        Assert.Null(DokuVaultClient.MatchNetwork(networks, IPAddress.Parse("10.0.0.1"), null));
    }

    [Fact]
    public async Task Find_documented_confirms_exact_address()
    {
        var (client, server) = Make();
        server.On("GET /api/mobile/search?q=10.0.0.1", HttpStatusCode.OK, new[]
        {
            new { type = "iotdevice", title = "IoT-Geräte", hits = new object[]
            {
                new { type = "iotdevice", id = 1, name = "Zehn", customer = new { slug = "acme", name = "Acme" } },
                new { type = "iotdevice", id = 2, name = "Fremd", customer = new { slug = "other", name = "Other" } },
                new { type = "iotdevice", id = 3, name = "Eins", customer = new { slug = "acme", name = "Acme" } },
            } },
        });
        server.On("GET /api/mobile/objects/iotdevice/1", HttpStatusCode.OK,
            new { type = "iotdevice", id = 1, name = "Zehn", ip_addresses = new[] { new { id = 9, dhcp = false, address = "10.0.0.10" } } });
        server.On("GET /api/mobile/objects/iotdevice/3", HttpStatusCode.OK,
            new { type = "iotdevice", id = 3, name = "Eins", ip_addresses = new[] { new { id = 8, dhcp = false, address = "10.0.0.1" } } });

        var found = await client.FindDocumentedAsync("acme", "10.0.0.1", CancellationToken.None);
        Assert.Equal("Eins", found!.Name);
        Assert.DoesNotContain(server.Requests, r => r.Path.EndsWith("/iotdevice/2"));
    }
}

public class ImporterTests
{
    private static ImportRequest Request() => new("acme", "iotdevice",
        new Dictionary<string, object?> { ["site_id"] = "3", ["name"] = "Shelly Flur" },
        IPAddress.Parse("192.168.1.150"), 5, "MAC 24:0A:C4:00:00:01");

    [Fact]
    public async Task Creates_then_attaches_address()
    {
        var server = new FakeServer()
            .On("POST /api/mobile/customers/acme/iotdevice", HttpStatusCode.Created, new { type = "iotdevice", id = 7, name = "Shelly Flur" })
            .On("POST /api/mobile/objects/iotdevice/7/ip-addresses", HttpStatusCode.Created,
                new[] { new { id = 1, dhcp = false, address = "192.168.1.150", label = "MAC 24:0A:C4:00:00:01", network = "LAN" } });
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var result = await new DeviceImporter(client).ImportAsync(Request(), CancellationToken.None);

        Assert.Equal(ImportOutcome.Created, result.Outcome);
        Assert.Equal(7, result.Id);
        var ip = JsonDocument.Parse(server.Requests[1].Body!).RootElement;
        Assert.Equal("192.168.1.150", ip.GetProperty("address").GetString());
        Assert.Equal(5, ip.GetProperty("network_id").GetInt32());
        Assert.Equal("MAC 24:0A:C4:00:00:01", ip.GetProperty("label").GetString());
    }

    [Fact]
    public async Task Taken_address_moves_the_new_device_back_to_the_trash()
    {
        var server = new FakeServer()
            .On("POST /api/mobile/customers/acme/iotdevice", HttpStatusCode.Created, new { type = "iotdevice", id = 7, name = "Shelly Flur" })
            .On("POST /api/mobile/objects/iotdevice/7/ip-addresses", HttpStatusCode.UnprocessableEntity,
                new { message = "x", errors = new { address = new[] { "Diese Adresse ist bei diesem Kunden schon vergeben." } } })
            .On("DELETE /api/mobile/objects/iotdevice/7", HttpStatusCode.NoContent, "");
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var result = await new DeviceImporter(client).ImportAsync(Request(), CancellationToken.None);

        Assert.Equal(ImportOutcome.AlreadyDocumented, result.Outcome);
        Assert.Contains("schon vergeben", result.Message);
        Assert.Contains(server.Requests, r => r.Method == HttpMethod.Delete);
    }

    [Fact]
    public async Task Validation_error_on_create_is_returned_per_field()
    {
        var server = new FakeServer()
            .On("POST /api/mobile/customers/acme/iotdevice", HttpStatusCode.UnprocessableEntity,
                new { message = "x", errors = new { site_id = new[] { "Die Auswahl für Standort gehört nicht zu diesem Kunden." } } });
        var client = new DokuVaultClient(new Uri("https://doku.example.com"), "1|abc", server);

        var result = await new DeviceImporter(client).ImportAsync(Request(), CancellationToken.None);

        Assert.Equal(ImportOutcome.Failed, result.Outcome);
        Assert.Equal("Die Auswahl für Standort gehört nicht zu diesem Kunden.", result.Message);
        Assert.True(result.FieldErrors!.ContainsKey("site_id"));
        Assert.Single(server.Requests);
    }
}
