using System.Text.Json;
using System.Text.Json.Serialization;

namespace DokuVault.Scanner.Core.Api;

// Response shapes of /api/mobile, see docs/mobile-api.md in the DokuVault
// repository. Responses are snake_case; unknown keys are ignored, so the
// server may add fields without breaking the app.

public sealed record Customer(
    [property: JsonPropertyName("slug")] string Slug,
    [property: JsonPropertyName("name")] string Name)
{
    public override string ToString() => Name;
}

public sealed record UserRights(
    [property: JsonPropertyName("passwords")] bool Passwords,
    [property: JsonPropertyName("trash")] bool Trash);

public sealed record User(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("customer")] Customer? Customer);

public sealed record TokenResponse(
    [property: JsonPropertyName("token")] string? Token,
    [property: JsonPropertyName("expires_at")] DateTimeOffset? ExpiresAt,
    [property: JsonPropertyName("user")] User? User,
    [property: JsonPropertyName("two_factor")] bool TwoFactor,
    [property: JsonPropertyName("challenge")] string? Challenge);

public sealed record FormOption(
    [property: JsonPropertyName("value")] string Value,
    [property: JsonPropertyName("label")] string Label)
{
    public override string ToString() => Label;
}

public sealed record FormField(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("label")] string Label,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("group")] string? Group,
    [property: JsonPropertyName("required")] bool Required,
    [property: JsonPropertyName("secret")] bool Secret,
    [property: JsonPropertyName("multiple")] bool Multiple,
    [property: JsonPropertyName("placeholder")] string? Placeholder,
    [property: JsonPropertyName("options")] IReadOnlyList<FormOption>? Options);

public sealed record ObjectForm(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("singular")] string Singular,
    [property: JsonPropertyName("fields")] IReadOnlyList<FormField> Fields,
    [property: JsonPropertyName("values")] Dictionary<string, JsonElement>? Values)
{
    /// <summary>The sites of the customer, from the "standort" field.</summary>
    public IReadOnlyList<FormOption> Sites =>
        Fields.FirstOrDefault(f => f.Kind == "standort" || f.Name == "site_id")?.Options ?? Array.Empty<FormOption>();
}

public sealed record ObjectSummary(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("subtitle")] string? Subtitle,
    [property: JsonPropertyName("customer")] Customer? Customer);

public sealed record IpEntry(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("dhcp")] bool Dhcp,
    [property: JsonPropertyName("address")] string Address,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("network")] string? Network);

public sealed record ObjectDetail(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("ip_addresses")] IReadOnlyList<IpEntry>? IpAddresses);

public sealed record NetworkSite(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name);

public sealed record NetworkEntry(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("network")] string? Network,
    [property: JsonPropertyName("subnet_mask")] string? SubnetMask,
    [property: JsonPropertyName("cidr")] int? Cidr,
    [property: JsonPropertyName("gateway")] string? Gateway,
    [property: JsonPropertyName("site")] NetworkSite? Site,
    [property: JsonPropertyName("error")] string? Error);

public sealed record NetworkList(
    [property: JsonPropertyName("entries")] IReadOnlyList<NetworkEntry> Entries);

public sealed record PlanDevice(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("type")] string? Type,
    [property: JsonPropertyName("id")] int? Id,
    [property: JsonPropertyName("in_pool")] bool InPool);

public sealed record PlanRow(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("from")] string? From,
    [property: JsonPropertyName("to")] string? To,
    [property: JsonPropertyName("gateway")] bool Gateway,
    [property: JsonPropertyName("devices")] IReadOnlyList<PlanDevice>? Devices);

public sealed record NetworkDetail(
    [property: JsonPropertyName("id")] int Id,
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("rows")] IReadOnlyList<PlanRow>? Rows,
    [property: JsonPropertyName("truncated")] JsonElement Truncated,
    [property: JsonPropertyName("dhcp_outside_range")] IReadOnlyList<PlanDevice>? DhcpOutsideRange);

public sealed record SearchGroup(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("hits")] IReadOnlyList<ObjectSummary> Hits);

public sealed record ListResponse(
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("may_create")] bool MayCreate);

/// <summary>
/// What the IP plans say: the documented addresses, all VLANs, and the VLANs
/// read completely - only inside those is "not listed" the same as "free".
/// </summary>
public sealed record DocumentedSet(
    IReadOnlyList<DocumentedAddress> Addresses,
    IReadOnlyList<NetworkEntry> Networks,
    IReadOnlyList<NetworkEntry> Covered,
    IReadOnlyList<string> Warnings);

/// <summary>An address that DokuVault already holds, with who holds it.</summary>
public sealed record DocumentedAddress(string Address, string? Name, string? Type, int? Id, int? NetworkId, string? NetworkName);
