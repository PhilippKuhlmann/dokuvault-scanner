namespace DokuVault.Scanner.Core.Scanning;

/// <summary>
/// Guesses from the scan findings which DokuVault type a device is: printer,
/// IoT device, camera, access point, switch, router, NAS, UPS, phone …
/// Only a suggestion: the user decides in the list, and every reason is
/// shown so the guess can be checked.
/// </summary>
public static class DeviceClassifier
{
    /// <summary>The ports every host is probed on.</summary>
    public static readonly int[] Ports =
    {
        22, 23, 53, 80, 139, 389, 443, 445, 515, 554, 631, 1883, 3389, 3493, 5000, 5001, 5060, 5985, 6668, 8006,
        8008, 8009, 8080, 8443, 8883, 9100,
    };

    private const int Threshold = 20;

    private static readonly string[] PrinterVendors =
    {
        "Brother", "Canon", "Epson", "Seiko Epson", "Kyocera", "Ricoh", "Xerox", "Lexmark", "Konica", "Sharp", "OKI",
        "Oki Data", "Toshiba Tec", "Zebra", "Develop", "Utax", "Triumph-Adler", "Fuji Xerox", "FUJIFILM Business",
        "Dymo", "Sato",
    };

    private static readonly string[] IotVendors =
    {
        "Espressif", "Shelly", "Allterco", "Tuya", "Signify", "Philips Lighting", "ITEAD", "Sonos", "Amazon",
        "Google", "Nest", "Xiaomi", "Beijing Xiaomi", "Lumi United", "Aqara", "Yeelight", "Ring", "Netatmo", "ecobee",
        "Nanoleaf", "LIFX", "WiZ", "Meross", "Govee", "Eve Systems", "Elgato", "Belkin", "Withings",
        "Somfy", "Bosch Thermotechnik", "Robert Bosch Smart Home", "Homematic", "eQ-3", "Loxone",
        "Raspberry Pi", "Wemo", "Chamberlain", "Rachio", "Tado", "SwitchBot", "Wonderlabs",
        "Hunter Douglas", "Sense Labs", "Fronius", "SMA Solar", "Kostal", "SolarEdge", "Huawei Device", "Viessmann",
        "Vaillant", "Miele", "BSH Hausgeräte", "BSH Hausgerate", "Panasonic", "Daikin", "Mitsubishi Electric",
        "Wallbox", "go-e", "KEBA", "Easee", "Zigbee", "Texas Instruments", "Silicon Laboratories", "Nordic Semiconductor",
        "Realtek Semiconductor", "Beken", "Bouffalo", "Hui Zhou Gaoshengda", "AzureWave", "Universal Global Scientific",
        "Murata", "Chongqing Fugui", "Sagemcom", "Hon Hai", "Liteon",
    };

    // Only the clearly IoT ones count as strong; chipset makers (Realtek,
    // Murata, AzureWave …) sit in laptops too.
    private static readonly string[] WeakIotVendors =
    {
        "Texas Instruments", "Silicon Laboratories", "Nordic Semiconductor", "Realtek Semiconductor", "AzureWave",
        "Universal Global Scientific", "Murata", "Chongqing Fugui", "Sagemcom", "Hon Hai", "Liteon", "Panasonic",
        "Hui Zhou Gaoshengda", "Raspberry Pi",
    };

    private static readonly string[] CameraVendors =
    {
        "Hikvision", "Hangzhou Hikvision", "Dahua", "Zhejiang Dahua", "Axis Communications", "Mobotix", "Reolink",
        "Arlo", "Ezviz", "Imou", "Hanwha", "Samsung Techwin", "Uniview", "Vivotek", "Bosch Security", "Avigilon",
        "Milesight", "Foscam", "Amcrest", "Instar",
    };

    private static readonly string[] NasVendors =
    {
        "Synology", "QNAP", "Asustor", "TerraMaster", "Western Digital", "Buffalo", "Netgear ReadyNAS", "Drobo",
    };

    private static readonly string[] UpsVendors =
    {
        "American Power Conversion", "APC", "Schneider Electric", "Eaton", "CyberPower", "Cyber Power", "Riello",
        "Socomec", "Legrand", "Vertiv", "Liebert", "Powerware", "Online USV", "AEG Power",
    };

    private static readonly string[] PhoneVendors =
    {
        "Yealink", "Snom", "Polycom", "Poly", "Grandstream", "Fanvil", "Mitel", "Aastra", "Avaya", "Alcatel-Lucent Enterprise",
        "Unify", "Siemens Enterprise", "Htek", "Akuvox", "Auerswald",
    };

    private static readonly string[] PhoneSystemWords =
    {
        "starface", "3cx", "agfeo", "auerswald", "asterisk", "freepbx", "swyx", "innovaphone", "elmeg", "compact 5",
        "telefonanlage", "pbx",
    };

    private static readonly string[] DectWords =
    {
        "dect", "n870", "n670", "n510", "w60b", "w70b", "w80b", "w90b", "m300", "m400", "m700", "m900", "ascom",
        "spectralink", "basisstation",
    };

    private static readonly string[] FirewallVendors =
    {
        "Fortinet", "Sophos", "WatchGuard", "Palo Alto", "Securepoint", "Netgate", "Check Point", "SonicWall",
        "Barracuda", "Stormshield", "genua", "LANCOM R&S", "Deciso",
    };

    private static readonly string[] FirewallWords =
    {
        "pfsense", "opnsense", "fortigate", "sophos", "securepoint", "watchguard", "sonicwall", "unifi os", "unifi dream",
        "udm", "usg", "firewall", "utm",
    };

    private static readonly string[] SwitchVendors =
    {
        "Hewlett Packard Enterprise", "Aruba", "Netgear", "Zyxel", "Allied Telesis", "Extreme Networks", "Mellanox",
        "Juniper", "D-Link", "TP-LINK", "TP-Link", "Edimax", "Cisco", "Meraki", "MikroTik", "Routerboard",
    };

    private static readonly string[] AccessPointVendors = { "Ruckus", "Cambium", "Aerohive", "Mist Systems", "Engenius", "Ubiquiti" };

    private static readonly string[] RouterVendors =
    {
        "AVM", "FRITZ!", "Draytek", "Teltonika", "Peplink", "LANCOM", "Lantronix", "Linksys", "Sagemcom", "Technicolor",
        "Huawei Technologies", "ZTE", "Speedport",
    };

    private static readonly string[] NetworkVendors =
        FirewallVendors.Concat(SwitchVendors).Concat(AccessPointVendors).Concat(RouterVendors).Distinct().ToArray();

    private static readonly string[] SwitchWords = { "switch", "usw", "sw-", "sw0", "edgeswitch", "procurve", "gs1", "gs3", "xgs" };
    private static readonly string[] AccessPointWords = { "ap-", "ap0", "uap", "u6-", "u7-", "accesspoint", "access point", "wap" };
    private static readonly string[] UpsWords = { "ups", "usv", "smart-ups", "network management card" };
    private static readonly string[] NasWords = { "diskstation", "rackstation", "nas", "qts", "synology", "truenas", "freenas", "unraid" };

    private static readonly string[] IotTitleWords =
    {
        "shelly", "tasmota", "esphome", "sonoff", "wled", "openbeken", "hue", "homematic", "ccu3", "loxone", "fronius",
        "inverter", "wechselrichter", "smart meter", "tibber", "zigbee", "deconz", "phoscon", "home assistant",
        "thermostat", "wallbox", "heizung", "solar", "klima", "awtrix", "openhab", "iobroker", "node-red",
    };

    private static readonly string[] CameraWords =
    {
        "unifi protect", "camera", "kamera", "ipcam", "ip camera", "network camera", "doorbell", "hikvision", "dahua",
        "reolink", "axis", "mobotix",
    };

    private static readonly string[] RecorderWords = { "nvr", "dvr", "recorder", "unifi nvr", "blue iris", "synology surveillance" };

    // Device names IoT firmware gives itself (Shelly, ESPHome, Tasmota …).
    private static readonly string[] IotNameWords =
    {
        "shelly", "esphome", "esp-", "esp32", "esp8266", "tasmota", "sonoff", "awtrix", "tibber", "wled", "hue",
        "echo-", "alexa", "tado", "homematic", "ccu3", "fronius", "wallbox", "go-echarger", "zigbee", "matter",
        "thermostat", "steckdose", "smartplug", "plug-", "tuya", "nuki",
        "meross", "govee", "nanoleaf", "wiz_", "yeelink", "roborock", "valetudo", "openbeken", "deconz", "conbee",
    };

    // Default host names of printers: HP "NPI3A1B2C", Brother "BRW0080927AFBCE",
    // Epson "EPSON3A1B2C", Konica "KMBT…" - prefix plus hex, so "brwilson" is none.
    private static readonly System.Text.RegularExpressions.Regex PrinterHostName = new(
        @"^(npi|brn|brw|epson|canon|kyocera|ricoh|xerox|lexmark|kmbt)[0-9a-f]{6,}(\.|$)",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static bool IsPrinterHostName(string name) => PrinterHostName.IsMatch(name);

    private static readonly string[] PrinterNameWords = { "printer", "drucker", "laserjet", "officejet", "mfc-", "pixma", "ecosys", "bizhub" };

    private static readonly string[] PrinterTitleWords =
    {
        "printer", "drucker", "laserjet", "officejet", "deskjet", "pagewide", "imageclass", "imagerunner", "ecosys",
        "taskalfa", "bizhub", "workcentre", "versalink", "altalink", "mfc-", "dcp-", "hl-", "pixma", "maxify",
        "workforce", "ecotank", "aficio", "ricoh", "kyocera", "web image monitor", "embedded web server",
        "remote ui", "command center", "syncthru", "topaccess",
    };

    /// <summary>SNMP enterprise numbers that tell the kind of device.</summary>
    private static readonly Dictionary<int, (DeviceKind Kind, string Vendor)> EnterpriseKinds = new()
    {
        [318] = (DeviceKind.Ups, "APC"),
        [534] = (DeviceKind.Ups, "Eaton"),
        [3808] = (DeviceKind.Ups, "CyberPower"),
        [6574] = (DeviceKind.Nas, "Synology"),
        [24681] = (DeviceKind.Nas, "QNAP"),
        [12356] = (DeviceKind.Firewall, "Fortinet"),
        [25461] = (DeviceKind.Firewall, "Palo Alto"),
    };

    private static readonly Dictionary<string, (DeviceKind Kind, int Score)> ServiceSignals = new()
    {
        ["_ipp._tcp.local"] = (DeviceKind.Printer, 50),
        ["_ipps._tcp.local"] = (DeviceKind.Printer, 50),
        ["_printer._tcp.local"] = (DeviceKind.Printer, 45),
        ["_pdl-datastream._tcp.local"] = (DeviceKind.Printer, 50),
        // A multifunction device announces both; the printer signals win there.
        ["_scanner._tcp.local"] = (DeviceKind.Scanner, 40),
        ["_uscan._tcp.local"] = (DeviceKind.Scanner, 40),
        ["_hap._tcp.local"] = (DeviceKind.IoT, 55),
        ["_homekit._tcp.local"] = (DeviceKind.IoT, 50),
        ["_matter._tcp.local"] = (DeviceKind.IoT, 55),
        ["_matterc._udp.local"] = (DeviceKind.IoT, 55),
        ["_googlecast._tcp.local"] = (DeviceKind.IoT, 45),
        ["_airplay._tcp.local"] = (DeviceKind.IoT, 25),
        ["_raop._tcp.local"] = (DeviceKind.IoT, 25),
        ["_spotify-connect._tcp.local"] = (DeviceKind.IoT, 35),
        ["_shelly._tcp.local"] = (DeviceKind.IoT, 70),
        ["_esphomelib._tcp.local"] = (DeviceKind.IoT, 70),
        ["_hue._tcp.local"] = (DeviceKind.IoT, 70),
        ["_mqtt._tcp.local"] = (DeviceKind.IoT, 40),
        ["_sonos._tcp.local"] = (DeviceKind.IoT, 60),
        ["_amzn-wplay._tcp.local"] = (DeviceKind.IoT, 60),
        ["_miio._udp.local"] = (DeviceKind.IoT, 60),
        ["_axis-video._tcp.local"] = (DeviceKind.Camera, 60),
    };

    public static DeviceSuggestion Classify(ScannedDevice d)
    {
        var scores = new Dictionary<DeviceKind, int>();
        var reasons = new Dictionary<DeviceKind, List<string>>();

        void Add(DeviceKind kind, int score, string reason)
        {
            scores[kind] = scores.GetValueOrDefault(kind) + score;
            if (!reasons.TryGetValue(kind, out var list))
                reasons[kind] = list = new List<string>();
            if (!list.Contains(reason))
                list.Add(reason);
        }

        bool Port(int p) => d.OpenPorts.Contains(p);
        var vendor = d.Manufacturer ?? "";
        var macVendor = d.MacVendor ?? "";
        var title = (d.Http?.Title ?? "") + " " + (d.Http?.Server ?? "");
        var snmp = (d.Snmp?.Description ?? "") + " " + (d.Snmp?.DeviceDescription ?? "");
        var upnpType = d.Upnp?.DeviceType ?? "";
        var model = d.Model ?? "";
        // Names count once per kind, however many of them a device has.
        var names = d.AllNames.ToList();
        string? Vendor(string[] list) => Matches(macVendor, list) ?? Matches(vendor, list);
        string? Named(string[] words) => names.FirstOrDefault(n => Matches(n, words) is not null);

        // ---- printer and scanner
        if (d.Snmp?.DeviceType == SnmpClient.HrDevicePrinter)
            Add(DeviceKind.Printer, 70, "meldet sich per SNMP als Drucker");
        else if (d.Snmp?.SerialNumber is not null)
            Add(DeviceKind.Printer, 60, "liefert die Drucker-MIB (Seriennummer)");
        if (Port(9100)) Add(DeviceKind.Printer, 40, "Port 9100 (RAW-Druck) offen");
        if (Port(631)) Add(DeviceKind.Printer, 25, "Port 631 (IPP) offen");
        if (Port(515)) Add(DeviceKind.Printer, 25, "Port 515 (LPD) offen");
        if (upnpType.Contains("printer", StringComparison.OrdinalIgnoreCase))
            Add(DeviceKind.Printer, 40, "UPnP-Gerätetyp Drucker");
        if (Vendor(PrinterVendors) is { } pv)
            Add(DeviceKind.Printer, 20, $"Hersteller {pv}");
        if (Matches(title, PrinterTitleWords) is { } pw)
            Add(DeviceKind.Printer, 25, $"Weboberfläche nennt „{pw}“");
        if (names.FirstOrDefault(IsPrinterHostName) is { } printerHost)
            Add(DeviceKind.Printer, 25, $"Name „{printerHost}“ (typisch für Drucker)");
        else if (Named(PrinterNameWords) is { } printerName)
            Add(DeviceKind.Printer, 25, $"Name „{printerName}“");

        // ---- announced services (IoT, scanner, camera)
        foreach (var service in d.Mdns)
        {
            if (ServiceSignals.TryGetValue(service.ServiceType, out var signal))
                Add(signal.Kind, signal.Score, $"mDNS-Dienst {ScannedDevice.ServiceLabel(service.ServiceType)}");
        }

        // ---- camera and recorder
        if (Vendor(CameraVendors) is { } cv)
            Add(DeviceKind.Camera, 40, $"Hersteller {cv}");
        if (Port(554)) Add(DeviceKind.Camera, 30, "Port 554 (RTSP-Video) offen");
        if (Matches(title, CameraWords) is { } cw)
            Add(DeviceKind.Camera, 45, $"Weboberfläche nennt „{cw}“");
        if (Named(CameraWords) is { } camName)
            Add(DeviceKind.Camera, 35, $"Name „{camName}“");
        if ((Matches(title, RecorderWords) ?? Named(RecorderWords)) is { } rw)
        {
            Add(DeviceKind.Recorder, 60, $"„{rw}“ (Videorekorder)");
            // A recorder carries everything a camera does - and is none.
            if (scores.TryGetValue(DeviceKind.Camera, out var camera))
                Add(DeviceKind.Recorder, camera, "Kamerahersteller bzw. Videodienste");
        }

        // ---- IoT
        if (Named(IotNameWords) is { } iotName)
            Add(DeviceKind.IoT, 40, $"Name „{iotName}“");
        if (Vendor(IotVendors) is { } iotVendor)
        {
            bool weak = Matches(iotVendor, WeakIotVendors) is not null;
            Add(DeviceKind.IoT, weak ? 10 : 35, $"Hersteller {iotVendor}");
        }
        if (Port(1883) || Port(8883)) Add(DeviceKind.IoT, 40, "MQTT-Port offen");
        if (Port(6668)) Add(DeviceKind.IoT, 45, "Port 6668 (Tuya) offen");
        if (Port(8008) || Port(8009)) Add(DeviceKind.IoT, 30, "Cast-Port offen");
        if (Matches(title, IotTitleWords) is { } iw)
            Add(DeviceKind.IoT, 40, $"Weboberfläche nennt „{iw}“");
        if (upnpType.Contains("MediaRenderer", StringComparison.OrdinalIgnoreCase) ||
            upnpType.Contains("ZonePlayer", StringComparison.OrdinalIgnoreCase) ||
            upnpType.Contains("Basic", StringComparison.OrdinalIgnoreCase))
            Add(DeviceKind.IoT, 20, "UPnP-Gerät (Medien/Basis)");
        bool onlyWeb = d.OpenPorts.Count > 0 && d.OpenPorts.All(p => p is 80 or 443 or 8080 or 8443);
        if (onlyWeb && !d.MacRandomized)
            Add(DeviceKind.IoT, 15, "nur eine Weboberfläche offen");

        // ---- storage and power
        if (d.Snmp?.Enterprise is int ent && EnterpriseKinds.TryGetValue(ent, out var byEnterprise))
            Add(byEnterprise.Kind, 60, $"SNMP-Kennung von {byEnterprise.Vendor}");
        if (Vendor(NasVendors) is { } nasVendor)
            Add(DeviceKind.Nas, 45, $"Hersteller {nasVendor}");
        if ((Matches(title, NasWords) ?? Matches(snmp, NasWords) ?? Named(NasWords)) is { } nasWord)
            Add(DeviceKind.Nas, 35, $"„{nasWord}“");
        if (Port(5000) && Port(5001) && (Port(445) || Port(139)))
            Add(DeviceKind.Nas, 25, "Verwaltung auf 5000/5001 und SMB (typisch NAS)");
        if (Vendor(UpsVendors) is { } upsVendor)
            Add(DeviceKind.Ups, 50, $"Hersteller {upsVendor}");
        if ((Matches(title, UpsWords) ?? Matches(snmp, UpsWords) ?? Named(UpsWords)) is { } upsWord)
            Add(DeviceKind.Ups, 40, $"„{upsWord}“");
        if (Port(3493)) Add(DeviceKind.Ups, 35, "Port 3493 (NUT, USV-Dienst) offen");

        // ---- telephony
        if (Vendor(PhoneVendors) is { } phoneVendor)
            Add(DeviceKind.Phone, 45, $"Hersteller {phoneVendor}");
        if (Port(5060)) Add(DeviceKind.Phone, 20, "Port 5060 (SIP) offen");
        if ((Matches(title, PhoneSystemWords) ?? Named(PhoneSystemWords)) is { } pbx)
            Add(DeviceKind.PhoneSystem, 60, $"„{pbx}“ (Telefonanlage)");
        if ((Matches(title, DectWords) ?? Matches(model, DectWords) ?? Named(DectWords)) is { } dect)
            Add(DeviceKind.Dect, 55, $"„{dect}“ (DECT-Basis)");

        // ---- servers, VMs and computers
        if (ArpResolver.Hypervisor(d.Mac) is { } hypervisor)
            Add(DeviceKind.VirtualMachine, 55, $"virtuelle Netzwerkkarte ({hypervisor})");
        if (Port(8006) || title.Contains("Proxmox", StringComparison.OrdinalIgnoreCase))
            Add(DeviceKind.Server, 60, "Proxmox-Oberfläche");
        if (title.Contains("ESXi", StringComparison.OrdinalIgnoreCase) || title.Contains("vSphere", StringComparison.OrdinalIgnoreCase))
            Add(DeviceKind.Server, 60, "VMware-ESXi-Oberfläche");
        if (Port(389) && (Port(445) || Port(139)))
            Add(DeviceKind.Server, 45, "LDAP und SMB offen (Domänencontroller)");
        if (Port(3389)) Add(DeviceKind.Computer, 40, "Remotedesktop offen");
        if (Port(445) || Port(139)) Add(DeviceKind.Computer, 30, "Dateifreigabe (SMB) offen");
        if (Port(5985)) Add(DeviceKind.Computer, 30, "WinRM offen");
        if (d.MacRandomized) Add(DeviceKind.Computer, 25, "zufällige MAC (Handy/Laptop)");
        if (d.IsSelf) Add(DeviceKind.Computer, 100, "dieser Rechner");
        // A VM with Windows still is a VM.
        if (scores.ContainsKey(DeviceKind.VirtualMachine) && scores.TryGetValue(DeviceKind.Computer, out var pc))
            Add(DeviceKind.VirtualMachine, pc, "Dienste eines Rechners");

        // ---- network gear
        int network = 0;
        var networkReasons = new List<string>();
        void Net(int score, string reason)
        {
            network += score;
            networkReasons.Add(reason);
        }
        if (d.IsGateway) Net(60, "Standard-Gateway");
        if (Port(53)) Net(25, "DNS-Port offen");
        if (upnpType.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase))
            Net(50, "UPnP-Internet-Gateway");
        var netVendor = Vendor(NetworkVendors);
        if (netVendor is not null)
            Net(30, $"Hersteller {netVendor}");
        if (network > 0)
        {
            // Which kind of network gear: firewall, router, switch, access point.
            var kind = DeviceKind.Network;
            string? why = null;
            var firewallHint = Vendor(FirewallVendors) ?? Matches(title, FirewallWords) ?? Matches(model, FirewallWords)
                               ?? Named(FirewallWords);
            if (firewallHint is not null && (d.IsGateway || Vendor(FirewallVendors) is not null))
                (kind, why) = (DeviceKind.Firewall, $"„{firewallHint}“");
            else if (d.IsGateway || upnpType.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase) ||
                     Vendor(RouterVendors) is not null)
                (kind, why) = (DeviceKind.Router, d.IsGateway ? null : "Hersteller von Routern");
            else if ((Named(AccessPointWords) ?? Matches(model, AccessPointWords)) is { } ap)
                (kind, why) = (DeviceKind.AccessPoint, $"Name „{ap}“");
            else if ((Named(SwitchWords) ?? Matches(model, SwitchWords) ?? Matches(snmp, SwitchWords)) is { } sw)
                (kind, why) = (DeviceKind.Switch, $"„{sw}“");
            else if (Vendor(AccessPointVendors) is { } apVendor && !Port(80) && !Port(443))
                // Ubiquiti, Ruckus …: an AP answers on SSH only; a switch or
                // controller would have a web interface.
                (kind, why) = (DeviceKind.AccessPoint, $"nur SSH offen (typisch für {apVendor}-Accesspoints)");
            else if (Vendor(SwitchVendors) is { } swVendor)
                (kind, why) = (DeviceKind.Switch, $"Hersteller von Switches ({swVendor})");
            foreach (var reason in networkReasons)
                Add(kind, 0, reason);
            Add(kind, network + (why is null ? 0 : 10), why ?? networkReasons[0]);
        }

        if (scores.Count == 0)
            return new DeviceSuggestion(DeviceKind.Unknown, 0, Array.Empty<string>());

        // Exact kinds win a tie over the vaguer ones further down the enum.
        var best = scores.OrderByDescending(s => s.Value).ThenBy(s => s.Key).First();
        if (best.Value < Threshold)
            return new DeviceSuggestion(DeviceKind.Unknown, best.Value, reasons[best.Key]);
        return new DeviceSuggestion(best.Key, Math.Min(100, best.Value), reasons[best.Key]);
    }

    /// <summary>
    /// The first word found at the start of a word in the text: "Ring" in
    /// "Ring LLC" but not in "Spring", "hue" in "Philips Hue" but not in "Shuen".
    /// </summary>
    internal static string? Matches(string text, IEnumerable<string> words)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        foreach (var w in words)
        {
            int from = 0;
            while ((from = text.IndexOf(w, from, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                if (from == 0 || !char.IsLetterOrDigit(text[from - 1]))
                    return w;
                from++;
            }
        }
        return null;
    }
}
