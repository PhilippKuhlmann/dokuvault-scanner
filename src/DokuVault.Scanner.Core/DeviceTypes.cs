using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Core;

/// <summary>A DokuVault form type a scanned device can become.</summary>
public sealed record DeviceType(string Key, string Label, string Group, DeviceKind Kind);

/// <summary>
/// The DokuVault types that carry IP addresses (models with HasIpAddresses
/// and a form in config/forms.php) - the ones worth adding from a scan.
/// Keys and labels as in config/forms.php.
/// </summary>
public static class DeviceTypes
{
    public static readonly IReadOnlyList<DeviceType> All = new DeviceType[]
    {
        new("router", "Router", "Netzwerk", DeviceKind.Router),
        new("firewall", "Firewall", "Netzwerk", DeviceKind.Firewall),
        new("networkswitch", "Switch", "Netzwerk", DeviceKind.Switch),
        new("accesspoint", "Accesspoint", "Netzwerk", DeviceKind.AccessPoint),
        new("server", "Server", "Server & Speicher", DeviceKind.Server),
        new("vm", "VM", "Server & Speicher", DeviceKind.VirtualMachine),
        new("nas", "NAS", "Server & Speicher", DeviceKind.Nas),
        new("ups", "USV", "Server & Speicher", DeviceKind.Ups),
        new("computer", "Computer", "Clients", DeviceKind.Computer),
        new("otherclient", "Sonstiger Client", "Clients", DeviceKind.OtherClient),
        new("printer", "Drucker", "Clients", DeviceKind.Printer),
        new("scanner", "Scanner", "Clients", DeviceKind.Scanner),
        new("iotdevice", "IoT-Gerät", "Clients", DeviceKind.IoT),
        new("machine", "Maschine", "Clients", DeviceKind.Machine),
        new("phone", "Telefon", "Telefonie", DeviceKind.Phone),
        new("phonesystem", "TK-Anlage", "Telefonie", DeviceKind.PhoneSystem),
        new("dect", "DECT", "Telefonie", DeviceKind.Dect),
        new("camera", "Kamera", "Kamera", DeviceKind.Camera),
        new("recorder", "Recorder", "Kamera", DeviceKind.Recorder),
    };

    public static DeviceType? ByKey(string? key) => All.FirstOrDefault(t => t.Key == key);

    public static DeviceType? ByKind(DeviceKind kind) => All.FirstOrDefault(t => t.Kind == kind);

    /// <summary>How a suggestion reads in the list, also for kinds without a type.</summary>
    public static string KindLabel(DeviceKind kind) => kind switch
    {
        DeviceKind.Network => "Netzwerkgerät",
        DeviceKind.Unknown => "unbekannt",
        _ => ByKind(kind)?.Label ?? kind.ToString(),
    };
}
