using System.Net;
using DokuVault.Scanner.Core;
using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Tests;

/// <summary>The suggestions for the DokuVault types beyond printer and IoT.</summary>
public class DeviceTypeTests
{
    private static ScannedDevice Device(string? mac = null, params int[] ports) => new()
    {
        Address = IPAddress.Parse("192.168.29.50"),
        Mac = mac,
        OpenPorts = ports,
    };

    private static DeviceKind Kind(ScannedDevice d) => DeviceClassifier.Classify(d).Kind;

    [Fact]
    public void Every_kind_with_a_type_maps_back()
    {
        Assert.Equal(19, DeviceTypes.All.Count);
        Assert.Equal(DeviceTypes.All.Count, DeviceTypes.All.Select(t => t.Key).Distinct().Count());
        foreach (var type in DeviceTypes.All)
            Assert.Same(type, DeviceTypes.ByKind(type.Kind));
        Assert.Null(DeviceTypes.ByKind(DeviceKind.Network));
        Assert.Equal("Netzwerkgerät", DeviceTypes.KindLabel(DeviceKind.Network));
    }

    [Fact]
    public void Unifi_protect_camera()
    {
        var d = Device("18:E8:29:08:05:63", 80, 443);
        d.MacVendor = "Ubiquiti Inc";
        d.DnsName = "hof.local";
        d.Http = new HttpInfo("https://192.168.29.50/", 200, null, "UniFi Protect");
        Assert.Equal(DeviceKind.Camera, Kind(d));
    }

    [Fact]
    public void Hikvision_with_rtsp_is_a_camera()
    {
        var d = Device("44:19:B6:00:00:01", 80, 554);
        d.MacVendor = "Hangzhou Hikvision Digital Technology Co.,Ltd.";
        Assert.Equal(DeviceKind.Camera, Kind(d));
    }

    [Fact]
    public void Nvr_is_a_recorder()
    {
        var d = Device("44:19:B6:00:00:02", 80, 554);
        d.MacVendor = "Hangzhou Hikvision Digital Technology Co.,Ltd.";
        d.Http = new HttpInfo("http://192.168.29.50/", 200, null, "NVR Login");
        Assert.Equal(DeviceKind.Recorder, Kind(d));
    }

    [Fact]
    public void Ubiquiti_with_ssh_only_is_an_access_point()
    {
        var d = Device("F0:9F:C2:CE:BD:8A", 22);
        d.MacVendor = "Ubiquiti Inc";
        Assert.Equal(DeviceKind.AccessPoint, Kind(d));
    }

    [Fact]
    public void Named_switch()
    {
        var d = Device("74:83:C2:20:E9:FC", 22, 80, 443);
        d.MacVendor = "Ubiquiti Inc";
        d.DnsName = "usw-keller.local";
        Assert.Equal(DeviceKind.Switch, Kind(d));
    }

    [Fact]
    public void Unifi_gateway_is_a_firewall()
    {
        var d = Device("74:AC:B9:1C:84:81", 22, 53, 80, 443);
        d.IsGateway = true;
        d.MacVendor = "Ubiquiti Inc";
        d.Http = new HttpInfo("https://192.168.29.1/", 200, null, "UniFi OS");
        Assert.Equal(DeviceKind.Firewall, Kind(d));
    }

    [Fact]
    public void Synology_by_snmp_is_a_nas()
    {
        var d = Device("00:11:32:00:00:01", 80, 443, 445, 5000, 5001);
        d.Snmp = new SnmpInfo("Linux DiskStation 4.4.302+", "1.3.6.1.4.1.6574.1", "DS920", null, null, null, null);
        Assert.Equal(DeviceKind.Nas, Kind(d));
    }

    [Fact]
    public void Apc_card_is_a_ups()
    {
        var d = Device("00:C0:B7:00:00:01", 80, 443);
        d.MacVendor = "American Power Conversion Corp";
        d.Snmp = new SnmpInfo("APC Web/SNMP Management Card", "1.3.6.1.4.1.318.1.3.27", "ups-serverraum", null, null, null, null);
        Assert.Equal(DeviceKind.Ups, Kind(d));
    }

    [Fact]
    public void Yealink_phone()
    {
        var d = Device("80:5E:C0:00:00:01", 80, 443, 5060);
        d.MacVendor = "YEALINK(XIAMEN) NETWORK TECHNOLOGY CO.,LTD.";
        Assert.Equal(DeviceKind.Phone, Kind(d));
    }

    [Fact]
    public void Starface_is_a_phone_system()
    {
        var d = Device("00:50:56:00:00:01", 80, 443, 5060);
        d.Http = new HttpInfo("https://192.168.29.50/", 200, null, "STARFACE");
        // A virtual appliance - the phone system is what matters.
        Assert.Equal(DeviceKind.PhoneSystem, Kind(d));
    }

    [Fact]
    public void Proxmox_mac_is_a_vm_and_not_randomized()
    {
        var d = Device("BC:24:11:BE:06:8D", 139, 445, 3389);
        Assert.False(d.MacRandomized);
        Assert.Equal(DeviceKind.VirtualMachine, Kind(d));
        var kvm = Device("52:54:00:12:34:56", 22);
        Assert.False(kvm.MacRandomized);
        Assert.Equal(DeviceKind.VirtualMachine, Kind(kvm));
    }

    [Fact]
    public void Proxmox_host_is_a_server()
    {
        var d = Device("0C:C4:7A:00:00:01", 22, 8006);
        Assert.Equal(DeviceKind.Server, Kind(d));
    }

    [Fact]
    public void Ip_scanner_without_printing_is_a_scanner()
    {
        var d = Device("00:80:92:00:00:01", 80);
        d.AddMdns(new MdnsService("_uscan._tcp.local", "Fujitsu fi-8170", new Dictionary<string, string>()));
        Assert.Equal(DeviceKind.Scanner, Kind(d));
    }

    [Fact]
    public void Multifunction_device_stays_a_printer()
    {
        var d = Device("3C:2A:F4:00:00:01", 80, 631, 9100);
        d.AddMdns(new MdnsService("_ipp._tcp.local", "Brother MFC-L2750DW", new Dictionary<string, string>()));
        d.AddMdns(new MdnsService("_uscan._tcp.local", "Brother MFC-L2750DW", new Dictionary<string, string>()));
        Assert.Equal(DeviceKind.Printer, Kind(d));
    }

    [Fact]
    public void Phone_with_random_mac_stays_untyped()
    {
        var d = Device("E2:7C:BA:41:0B:90");
        var s = DeviceClassifier.Classify(d);
        Assert.Equal(DeviceKind.Computer, s.Kind);
        Assert.True(s.Confidence < 30); // too weak to preselect a type
    }
}
