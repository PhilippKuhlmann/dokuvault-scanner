using System.Net;
using System.Text;
using DokuVault.Scanner.Core.Scanning;

namespace DokuVault.Scanner.Tests;

public class IpRangeTests
{
    [Fact]
    public void Cidr_leaves_out_network_and_broadcast()
    {
        Assert.True(IpRange.TryParse("192.168.1.77/24", out var range, out _));
        Assert.Equal(254, range!.Count);
        Assert.Equal("192.168.1.1", IpRange.ToAddress(range.First).ToString());
        Assert.Equal("192.168.1.254", IpRange.ToAddress(range.Last).ToString());
        Assert.Equal("192.168.1.0/24", range.ToString());
    }

    [Theory]
    [InlineData("10.0.0.10-10.0.0.20", 11)]
    [InlineData("10.0.0.10-20", 11)]
    [InlineData("10.0.0.5", 1)]
    [InlineData("10.0.0.0/31", 2)]
    [InlineData("10.0.0.9/32", 1)]
    public void Parses_spans_and_single_addresses(string text, long count)
    {
        Assert.True(IpRange.TryParse(text, out var range, out var error), error);
        Assert.Equal(count, range!.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData("10.0.0")]
    [InlineData("10.0.0.1/33")]
    [InlineData("10.0.0.20-10.0.0.10")]
    [InlineData("10.0.0.0/16")]
    [InlineData("fe80::1")]
    public void Rejects_invalid_or_too_large(string text)
    {
        Assert.False(IpRange.TryParse(text, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void Contains_and_prefix_from_mask()
    {
        var range = IpRange.FromCidr(IPAddress.Parse("172.16.4.1"), 22);
        Assert.True(range.Contains(IPAddress.Parse("172.16.7.254")));
        Assert.False(range.Contains(IPAddress.Parse("172.16.8.1")));
        Assert.Equal(22, IpRange.PrefixFromMask(IPAddress.Parse("255.255.252.0")));
    }
}

public class MacAndVendorTests
{
    [Fact]
    public void Detects_randomized_mac()
    {
        Assert.True(ArpResolver.IsRandomized("DA:A1:19:00:00:01"));
        Assert.False(ArpResolver.IsRandomized("24:0A:C4:00:00:01"));
    }

    [Fact]
    public void Parses_ieee_csv_with_quotes()
    {
        var csv = new[]
        {
            "Registry,Assignment,Organization Name,Organization Address",
            "MA-L,240AC4,Espressif Inc.,Shanghai CN",
            "MA-L,001122,\"Example, Ltd.\",\"Somewhere \"\"quoted\"\"\"",
            "MA-L,XYZ123,Broken,",
        };
        var vendors = OuiDatabase.Parse(csv);
        Assert.Equal(2, vendors.Count);
        Assert.Equal("Example, Ltd.", vendors["001122"]);
    }

    [Fact]
    public void Longest_registered_prefix_wins()
    {
        var db = OuiDatabase.FromLines(new[]
        {
            "MA-L,5847CA,IEEE Registration Authority,x",
            "MA-M,5847CA7,Small IoT Maker GmbH,x",
            "MA-S,5847CA7AB,Tiny Sensor Co.,x",
        });
        Assert.Equal("Tiny Sensor Co.", db.Lookup("58:47:CA:7A:B1:23"));
        Assert.Equal("Small IoT Maker GmbH", db.Lookup("58:47:CA:79:87:9C"));
        Assert.Equal("IEEE Registration Authority", db.Lookup("58:47:CA:00:00:01"));
        Assert.Null(ScannedDevice.ShortVendor("IEEE Registration Authority"));
        Assert.Null(db.Lookup("DA:A1:19:00:00:01"));
    }

    [Theory]
    [InlineData("Espressif Inc.", "Espressif")]
    [InlineData("Brother Industries, Ltd.", "Brother Industries")]
    [InlineData("Shelly Group AG", "Shelly Group")]
    [InlineData("Hewlett Packard", "Hewlett Packard")]
    public void Shortens_vendor_names(string raw, string expected) =>
        Assert.Equal(expected, ScannedDevice.ShortVendor(raw));
}

public class SnmpTests
{
    [Theory]
    [InlineData("1.3.6.1.2.1.1.1.0")]
    [InlineData("1.3.6.1.2.1.43.5.1.1.17.1")]
    [InlineData("1.3.6.1.4.1.18334.1.1")]
    public void Oid_round_trip(string oid) =>
        Assert.Equal(oid, SnmpClient.DecodeOid(SnmpClient.EncodeOid(oid)));

    [Fact]
    public void Parses_a_get_response()
    {
        // A GetResponse built with the request encoder, tag switched to 0xA2
        // and values filled in by hand.
        var response = BuildResponse(4711, new (string, byte, byte[])[]
        {
            (SnmpClient.SysDescr, 0x04, Encoding.ASCII.GetBytes("Brother NC-8300w\0")),
            (SnmpClient.SysObjectId, 0x06, SnmpClient.EncodeOid("1.3.6.1.4.1.2435.2.3.9.1")),
            (SnmpClient.HrDeviceType1, 0x06, SnmpClient.EncodeOid(SnmpClient.HrDevicePrinter)),
            (SnmpClient.PrtGeneralSerialNumber1, 0x04, Encoding.ASCII.GetBytes("E78123A4N567890")),
            (SnmpClient.SysName, 0x81, Array.Empty<byte>()), // noSuchInstance
        });

        var values = SnmpClient.ParseResponse(response, 4711);
        Assert.NotNull(values);
        Assert.Equal("Brother NC-8300w", values![SnmpClient.SysDescr]);
        Assert.Equal(SnmpClient.HrDevicePrinter, values[SnmpClient.HrDeviceType1]);
        Assert.False(values.ContainsKey(SnmpClient.SysName));

        var info = new SnmpInfo(values[SnmpClient.SysDescr], values[SnmpClient.SysObjectId], null, null,
            values[SnmpClient.HrDeviceType1], null, values[SnmpClient.PrtGeneralSerialNumber1]);
        Assert.True(info.IsPrinter);
        Assert.Equal(2435, info.Enterprise);

        Assert.Null(SnmpClient.ParseResponse(response, 1)); // other request id
    }

    [Fact]
    public void Request_is_well_formed()
    {
        var packet = SnmpClient.BuildGetRequest(1, "public", 300, new[] { SnmpClient.SysDescr });
        Assert.Equal(0x30, packet[0]);
        Assert.Equal(packet.Length - 2, packet[1]);
        Assert.Contains((byte)0xA0, packet);
    }

    private static byte[] BuildResponse(int requestId, (string Oid, byte Tag, byte[] Value)[] binds)
    {
        static byte[] Tlv(byte tag, byte[] value)
        {
            var list = new List<byte> { tag };
            if (value.Length < 0x80)
                list.Add((byte)value.Length);
            else
            {
                list.Add(0x82);
                list.Add((byte)(value.Length >> 8));
                list.Add((byte)value.Length);
            }
            list.AddRange(value);
            return list.ToArray();
        }
        static byte[] Int(int v)
        {
            var b = BitConverter.GetBytes(v).Reverse().SkipWhile((x, i) => x == 0 && i < 3).ToArray();
            if ((b[0] & 0x80) != 0)
                b = new byte[] { 0 }.Concat(b).ToArray();
            return b;
        }
        var varbinds = binds.SelectMany(b => Tlv(0x30, Tlv(0x06, SnmpClient.EncodeOid(b.Oid)).Concat(Tlv(b.Tag, b.Value)).ToArray())).ToArray();
        var pdu = Tlv(0xA2, Tlv(0x02, Int(requestId)).Concat(Tlv(0x02, Int(0))).Concat(Tlv(0x02, Int(0))).Concat(Tlv(0x30, varbinds)).ToArray());
        return Tlv(0x30, Tlv(0x02, Int(1)).Concat(Tlv(0x04, Encoding.ASCII.GetBytes("public"))).Concat(pdu).ToArray());
    }
}

public class MdnsTests
{
    [Fact]
    public void Parses_ptr_txt_and_a_records_with_compression()
    {
        var packet = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 2 };
        // answer: _ipp._tcp.local PTR "Brother HL._ipp._tcp.local"
        int serviceOffset = packet.Count;
        packet.AddRange(Name("_ipp._tcp.local"));
        packet.AddRange(new byte[] { 0, 12, 0, 1, 0, 0, 0, 120 });
        var instance = new List<byte> { 10 };
        instance.AddRange(Encoding.ASCII.GetBytes("Brother HL"));
        instance.Add(0xC0);
        instance.Add((byte)serviceOffset);
        packet.AddRange(new byte[] { 0, (byte)instance.Count });
        int instanceOffset = packet.Count;
        packet.AddRange(instance);
        // additional: TXT for the instance (pointer), ty=HL-L2350DW
        packet.AddRange(new byte[] { 0xC0, (byte)instanceOffset, 0, 16, 0x80, 1, 0, 0, 0, 120 });
        var txt = Encoding.ASCII.GetBytes("ty=Brother HL-L2350DW");
        packet.AddRange(new byte[] { 0, (byte)(txt.Length + 1), (byte)txt.Length });
        packet.AddRange(txt);
        // additional: A brother.local 192.168.1.40
        packet.AddRange(Name("brother.local"));
        packet.AddRange(new byte[] { 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 1, 40 });

        var services = MdnsBrowser.ParseResponse(packet.ToArray(), out var addresses);
        var service = Assert.Single(services);
        Assert.Equal("_ipp._tcp.local", service.ServiceType);
        Assert.Equal("Brother HL", service.InstanceName);
        Assert.Equal("Brother HL-L2350DW", service.Txt["ty"]);
        Assert.Equal(IPAddress.Parse("192.168.1.40"), Assert.Single(addresses));
    }

    [Fact]
    public void Query_asks_for_ptr_with_unicast_bit()
    {
        var query = MdnsBrowser.BuildQuery(new[] { "_hap._tcp.local" });
        Assert.Equal(1, query[5]);
        Assert.Equal(new byte[] { 0, 12, 0x80, 1 }, query[^4..]);
    }

    private static IEnumerable<byte> Name(string name)
    {
        foreach (var label in name.Split('.'))
        {
            yield return (byte)label.Length;
            foreach (var b in Encoding.ASCII.GetBytes(label))
                yield return b;
        }
        yield return 0;
    }
}

public class NetBiosTests
{
    [Fact]
    public void Request_encodes_wildcard_name()
    {
        var request = NetBiosResolver.BuildRequest(0x1234);
        Assert.Equal(50, request.Length);
        Assert.Equal((byte)'C', request[13]);
        Assert.Equal((byte)'K', request[14]);
        Assert.Equal(new byte[] { 0, 0x21, 0, 1 }, request[^4..]);
    }

    [Fact]
    public void Picks_the_unique_workstation_name()
    {
        var packet = new byte[57 + 3 * 18];
        packet[56] = 3;
        Write(packet, 0, "WORKGROUP", 0x00, group: true);
        Write(packet, 1, "NPI3A1B2C", 0x20, group: false);
        Write(packet, 2, "NPI3A1B2C", 0x00, group: false);
        Assert.Equal("NPI3A1B2C", NetBiosResolver.ParseResponse(packet));
    }

    private static void Write(byte[] packet, int index, string name, byte suffix, bool group)
    {
        int start = 57 + index * 18;
        Encoding.ASCII.GetBytes(name.PadRight(15)).CopyTo(packet, start);
        packet[start + 15] = suffix;
        packet[start + 16] = (byte)(group ? 0x80 : 0x00);
    }
}

public class SsdpAndHttpTests
{
    [Fact]
    public void Parses_ssdp_headers()
    {
        var headers = SsdpDiscovery.ParseHeaders("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.9:1400/xml/device_description.xml\r\nSERVER: Linux UPnP/1.0 Sonos/70.3\r\nST: upnp:rootdevice\r\n\r\n");
        Assert.Equal("http://192.168.1.9:1400/xml/device_description.xml", headers["location"]);
        Assert.Equal("upnp:rootdevice", headers["ST"]);
    }

    [Fact]
    public void Reads_upnp_description_and_refuses_dtds()
    {
        var xml = "<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><device><deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType>" +
                  "<friendlyName>Küche</friendlyName><manufacturer>Sonos, Inc.</manufacturer><modelName>Sonos One</modelName>" +
                  "<serialNumber>48-A6-B8-00-00-00:1</serialNumber></device></root>";
        var info = SsdpDiscovery.ParseDescription(xml);
        Assert.NotNull(info);
        Assert.Equal("Küche", info!.FriendlyName);
        Assert.Equal("Sonos One", info.ModelName);

        var evil = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><root><device><friendlyName>&x;</friendlyName></device></root>";
        Assert.Null(SsdpDiscovery.ParseDescription(evil));
    }

    [Theory]
    [InlineData("<html><head><TITLE>\n  Shelly 1PM &amp; Co </TITLE></head>", "Shelly 1PM & Co")]
    [InlineData("<html><body>no title</body></html>", null)]
    public void Extracts_html_title(string html, string? expected) =>
        Assert.Equal(expected, HttpProbe.ExtractTitle(html));
}

public class ClassifierTests
{
    private static ScannedDevice Device(params int[] ports)
    {
        var d = new ScannedDevice { Address = IPAddress.Parse("192.168.1.50") };
        d.OpenPorts = ports;
        return d;
    }

    [Fact]
    public void Printer_by_ports_and_snmp()
    {
        var d = Device(80, 443, 631, 9100);
        d.Snmp = new SnmpInfo("HP ETHERNET MULTI-ENVIRONMENT", "1.3.6.1.4.1.11.2.3.9.1", "NPI3A1B2C", null,
            SnmpClient.HrDevicePrinter, "HP LaserJet Pro M404dn", "VNB3K12345");
        var s = DeviceClassifier.Classify(d);
        Assert.Equal(DeviceKind.Printer, s.Kind);
        Assert.Equal("HP", d.Manufacturer);
        Assert.Equal("HP LaserJet Pro M404dn", d.Model);
        Assert.Equal("VNB3K12345", d.SerialNumber);
    }

    [Fact]
    public void Iot_by_mdns_and_vendor()
    {
        var d = Device(80);
        d.MacVendor = "Espressif Inc.";
        d.AddMdns(new MdnsService("_shelly._tcp.local", "shellyplus1pm-a8032ab12345", new Dictionary<string, string>()));
        var s = DeviceClassifier.Classify(d);
        Assert.Equal(DeviceKind.IoT, s.Kind);
        Assert.Contains(s.Reasons, r => r.Contains("Shelly"));
        Assert.Equal("Shelly", d.Manufacturer);
        Assert.Equal("shellyplus1pm", d.Model);
    }

    [Fact]
    public void Windows_pc_is_no_candidate()
    {
        var d = Device(135, 139, 445, 3389);
        d.NetBiosName = "PC-BUCHHALTUNG";
        Assert.Equal(DeviceKind.Computer, DeviceClassifier.Classify(d).Kind);
    }

    [Fact]
    public void Fritzbox_gateway_is_a_router()
    {
        var d = Device(53, 80, 443);
        d.IsGateway = true;
        d.MacVendor = "AVM Audiovisuelles Marketing und Computersysteme GmbH";
        Assert.Equal(DeviceKind.Router, DeviceClassifier.Classify(d).Kind);
    }

    [Fact]
    public void Nothing_known_stays_unknown()
    {
        Assert.Equal(DeviceKind.Unknown, DeviceClassifier.Classify(Device()).Kind);
    }

    [Fact]
    public void Shelly_plug_by_its_name()
    {
        var d = Device(80);
        d.MacVendor = "Espressif Inc.";
        d.DnsName = "shellyplug-s-F12978.fritz.box";
        var s = DeviceClassifier.Classify(d);
        Assert.Equal(DeviceKind.IoT, s.Kind);
        Assert.True(s.Confidence >= 80);
        Assert.Equal("shellyplug-s-F12978", d.BestName);
        Assert.Equal("Shelly", d.Manufacturer);
        Assert.Equal("shellyplug-s", d.Model);
    }

    [Theory]
    [InlineData("NPI3A1B2C", true)]
    [InlineData("BRW0080927AFBCE.local", true)]
    [InlineData("brwilson-laptop", false)]
    [InlineData("EPSON3A1B2C", true)]
    public void Printer_default_host_names(string name, bool printer)
    {
        var d = Device();
        d.NetBiosName = name;
        Assert.Equal(printer, DeviceClassifier.Classify(d).Kind == DeviceKind.Printer);
    }

    [Theory]
    [InlineData("BBBB408DDBB5@55OLED804/12+", "55OLED804/12+")]
    [InlineData("D11831270536734D-0535FDD6799B8831", null)]
    [InlineData("Philips Hue - 4B7826", "Philips Hue - 4B7826")]
    public void Mdns_instance_names(string instance, string? expected) =>
        Assert.Equal(expected, ScannedDevice.MdnsName(instance));

    [Fact]
    public void Punycode_host_names_are_decoded()
    {
        var d = Device(80);
        d.DnsName = "xn--haustr-7ya.kuhlmannit.local";
        Assert.Equal("haustür", d.BestName);
    }

    [Fact]
    public void Airplay_metadata_is_no_model()
    {
        var d = Device(5000);
        d.AddMdns(new MdnsService("_raop._tcp.local", "C869CD218984@Wohnzimmer",
            new Dictionary<string, string> { ["md"] = "0,1,2", ["am"] = "AppleTV11,1" }));
        Assert.Equal("AppleTV11,1", d.Model);
    }

    [Fact]
    public void Ipp_txt_record_gives_model()
    {
        var d = Device(631);
        d.AddMdns(new MdnsService("_ipp._tcp.local", "Brother HL-L2350DW series",
            new Dictionary<string, string> { ["ty"] = "Brother HL-L2350DW series", ["usb_MFG"] = "Brother" }));
        Assert.Equal(DeviceKind.Printer, DeviceClassifier.Classify(d).Kind);
        Assert.Equal("Brother HL-L2350DW series", d.Model);
        Assert.Equal("Brother", d.Manufacturer);
    }
}
