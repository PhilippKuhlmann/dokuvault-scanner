using System.Net;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// What the scan believes a device is - one per DokuVault type (see
/// DeviceTypes), plus Network for network gear it cannot tell apart.
/// </summary>
public enum DeviceKind
{
    Unknown,
    IoT,
    Printer,
    Scanner,
    Camera,
    Recorder,
    Nas,
    Ups,
    Phone,
    PhoneSystem,
    Dect,
    Server,
    VirtualMachine,
    Computer,
    OtherClient,
    Machine,
    Router,
    Firewall,
    Switch,
    AccessPoint,
    Network,
}

public sealed record DeviceSuggestion(DeviceKind Kind, int Confidence, IReadOnlyList<string> Reasons);

/// <summary>Everything one scan found out about one address.</summary>
public sealed class ScannedDevice
{
    public required IPAddress Address { get; init; }
    public string? Mac { get; set; }
    public bool MacRandomized => Mac is not null && ArpResolver.IsRandomized(Mac);
    public string? MacVendor { get; set; }
    public long? PingMs { get; set; }
    public string? DnsName { get; set; }
    public string? NetBiosName { get; set; }
    // Scan threads write while the UI reads: the lists are replaced as a
    // whole, never changed in place, so a reader always holds a snapshot.
    public IReadOnlyList<int> OpenPorts { get; set; } = Array.Empty<int>();
    public SnmpInfo? Snmp { get; set; }
    public HttpInfo? Http { get; set; }
    public IReadOnlyList<MdnsService> Mdns { get; set; } = Array.Empty<MdnsService>();

    public void AddMdns(MdnsService service) => AddMdns(new[] { service });

    /// <summary>Adds announcements that are new, as one replacement of the list.</summary>
    public void AddMdns(IEnumerable<MdnsService> services)
    {
        lock (this)
        {
            var known = Mdns;
            var added = services.Where(s => !known.Any(k => k.ServiceType == s.ServiceType && k.InstanceName == s.InstanceName)).ToList();
            if (added.Count > 0)
                Mdns = known.Concat(added).ToList();
        }
    }
    public UpnpInfo? Upnp { get; set; }
    public bool IsGateway { get; set; }
    public bool IsSelf { get; set; }
    public DeviceSuggestion Suggestion { get; set; } = new(DeviceKind.Unknown, 0, Array.Empty<string>());

    public uint SortKey => IpRange.ToUInt(Address);

    /// <summary>The most telling name: mDNS instance, UPnP, SNMP, NetBIOS, DNS.</summary>
    public string? BestName
    {
        get
        {
            var mdns = Mdns.Where(s => s.ServiceType != "_http._tcp.local").Select(s => MdnsName(s.InstanceName))
                           .FirstOrDefault(n => n is not null)
                       ?? Mdns.Select(s => MdnsName(s.InstanceName)).FirstOrDefault(n => n is not null);
            return Clean(Upnp?.FriendlyName) ?? Clean(mdns) ?? Clean(Snmp?.Name) ?? Clean(NetBiosName)
                   ?? Clean(ShortDns(DnsName));
        }
    }

    // Shelly devices name themselves "shellyplug-s-F12978": maker and model
    // are in the name, while the MAC only knows the chip (Espressif).
    private string? ShellyModel =>
        AllNames.Select(n => ShortDns(n) ?? n)
            .FirstOrDefault(n => n.StartsWith("shelly", StringComparison.OrdinalIgnoreCase) && n.Contains('-'))
            is { } name ? name[..name.LastIndexOf('-')] : null;

    public string? Manufacturer =>
        Clean(Upnp?.Manufacturer)
        ?? (ShellyModel is not null ? "Shelly" : null)
        ?? (Snmp?.Enterprise is int e && SnmpClient.Enterprises.TryGetValue(e, out var vendor) ? vendor : null)
        ?? Clean(Txt("usb_MFG")) ?? Clean(Txt("manufacturer"))
        ?? ShortVendor(MacVendor);

    // TXT keys mean different things per service: "md" is the model for
    // Cast and HomeKit, but the metadata types ("0,1,2") for AirPlay audio.
    public string? Model =>
        Clean(Txt("ty")) ?? Clean(Txt("usb_MDL")) ?? Clean(Txt("product")?.Trim('(', ')'))
        ?? Clean(Upnp?.ModelName is { } m ? (Upnp.ModelNumber is { } n && !m.Contains(n) ? $"{m} {n}" : m) : null)
        ?? Clean(Txt("md", "_googlecast._tcp.local", "_hap._tcp.local"))
        ?? Clean(Txt("model", "_airplay._tcp.local", "_shelly._tcp.local"))
        ?? Clean(Txt("am", "_raop._tcp.local"))
        ?? ShellyModel
        ?? Clean(Snmp?.DeviceDescription)
        ?? FirstLine(Snmp?.Description);

    public string? SerialNumber => Clean(Snmp?.SerialNumber) ?? Clean(Upnp?.SerialNumber);

    /// <summary>The web interface, if one answered: for the URL field of IoT devices.</summary>
    public string? WebUrl => Http?.Url.TrimEnd('/');

    public string PortsText => string.Join(", ", OpenPorts.OrderBy(p => p));

    public string ServicesText => string.Join(", ", Mdns.Select(s => ServiceLabel(s.ServiceType)).Distinct());

    private string? Txt(string key, params string[] services) =>
        Mdns.Where(s => services.Length == 0 || services.Contains(s.ServiceType))
            .Select(s => s.Txt.TryGetValue(key, out var v) ? v : null)
            .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

    /// <summary>All names the device goes by - for the classifier.</summary>
    public IEnumerable<string> AllNames =>
        new[] { DnsName, NetBiosName, Snmp?.Name, Upnp?.FriendlyName }
            .Concat(Mdns.Select(s => s.InstanceName))
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Select(n => n!);

    private static string? Clean(string? text)
    {
        text = text?.Trim();
        return string.IsNullOrEmpty(text) || text.Equals("unknown", StringComparison.OrdinalIgnoreCase) ? null : text;
    }

    private static string? FirstLine(string? text) =>
        Clean(text?.Split('\n', '\r', ';').FirstOrDefault());

    private static string? ShortDns(string? name)
    {
        if (name is null || IPAddress.TryParse(name, out _))
            return null;
        int dot = name.IndexOf('.');
        return Unicode(dot > 0 ? name[..dot] : name);
    }

    /// <summary>"xn--haustr-7ya" → "haustür".</summary>
    private static string Unicode(string label)
    {
        try
        {
            return label.Contains("xn--", StringComparison.OrdinalIgnoreCase)
                ? new System.Globalization.IdnMapping().GetUnicode(label)
                : label;
        }
        catch (ArgumentException)
        {
            return label;
        }
    }

    /// <summary>
    /// An mDNS instance as a name: AirPlay audio is "MAC@Name", Matter and
    /// some HomeKit devices announce nothing but an id - that is no name.
    /// </summary>
    internal static string? MdnsName(string? instance)
    {
        instance = Clean(instance);
        if (instance is null)
            return null;
        int at = instance.IndexOf('@');
        if (at is > 0 && at < instance.Length - 1 && instance[..at].All(Uri.IsHexDigit))
            instance = instance[(at + 1)..];
        var compact = instance.Replace("-", "").Replace(":", "");
        if (compact.Length >= 12 && compact.All(Uri.IsHexDigit))
            return null;
        return instance;
    }

    /// <summary>"Espressif Inc." → "Espressif"; legal forms do not belong in the documentation.</summary>
    internal static string? ShortVendor(string? vendor)
    {
        vendor = Clean(vendor);
        // The block holder of MA-M/MA-S ranges, not the manufacturer.
        if (vendor is null || vendor.StartsWith("IEEE Registration Authority", StringComparison.OrdinalIgnoreCase))
            return null;
        foreach (var suffix in new[]
                 {
                     " Co., Ltd.", " Co.,Ltd.", " Co., Ltd", " CO.,LTD", " Co.,Ltd", ", Inc.", " Inc.", " Inc", " Corporation",
                     " Corp.", " Ltd.", " Ltd", " GmbH & Co. KG", " GmbH", " AG", " LLC", " B.V.", " S.A.", " Limited",
                     " Technology", " Technologies",
                 })
        {
            if (vendor.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                vendor = vendor[..^suffix.Length].TrimEnd(',', ' ');
        }
        return vendor;
    }

    public static string ServiceLabel(string serviceType) => serviceType switch
    {
        "_ipp._tcp.local" or "_ipps._tcp.local" => "IPP",
        "_printer._tcp.local" => "LPD",
        "_pdl-datastream._tcp.local" => "RAW-Druck",
        "_scanner._tcp.local" or "_uscan._tcp.local" => "Scanner",
        "_hap._tcp.local" or "_homekit._tcp.local" => "HomeKit",
        "_matter._tcp.local" or "_matterc._udp.local" => "Matter",
        "_googlecast._tcp.local" => "Chromecast",
        "_airplay._tcp.local" => "AirPlay",
        "_raop._tcp.local" => "AirPlay-Audio",
        "_spotify-connect._tcp.local" => "Spotify",
        "_shelly._tcp.local" => "Shelly",
        "_esphomelib._tcp.local" => "ESPHome",
        "_hue._tcp.local" => "Hue",
        "_mqtt._tcp.local" => "MQTT",
        "_sonos._tcp.local" => "Sonos",
        "_amzn-wplay._tcp.local" => "Alexa",
        "_miio._udp.local" => "Xiaomi",
        "_axis-video._tcp.local" => "Kamera",
        "_http._tcp.local" => "Web",
        _ => serviceType.Replace(".local", ""),
    };
}
