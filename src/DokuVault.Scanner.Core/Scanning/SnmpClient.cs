using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DokuVault.Scanner.Core.Scanning;

/// <summary>What a device tells about itself over SNMP.</summary>
public sealed record SnmpInfo(
    string? Description,
    string? ObjectId,
    string? Name,
    string? Location,
    string? DeviceType,
    string? DeviceDescription,
    string? SerialNumber)
{
    /// <summary>hrDeviceType of the first device is hrDevicePrinter.</summary>
    public bool IsPrinter =>
        DeviceType == SnmpClient.HrDevicePrinter || SerialNumber is not null;

    /// <summary>The enterprise number from sysObjectID (1.3.6.1.4.1.&lt;n&gt;…).</summary>
    public int? Enterprise
    {
        get
        {
            const string prefix = "1.3.6.1.4.1.";
            if (ObjectId is null || !ObjectId.StartsWith(prefix, StringComparison.Ordinal))
                return null;
            var rest = ObjectId[prefix.Length..];
            int dot = rest.IndexOf('.');
            return int.TryParse(dot < 0 ? rest : rest[..dot], out int n) ? n : null;
        }
    }
}

/// <summary>
/// A minimal SNMP v2c/v1 GET client - enough to read model and serial number
/// off a printer. Read-only, one datagram per request.
/// </summary>
public static class SnmpClient
{
    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string SysLocation = "1.3.6.1.2.1.1.6.0";
    public const string HrDeviceType1 = "1.3.6.1.2.1.25.3.2.1.2.1";
    public const string HrDeviceDescr1 = "1.3.6.1.2.1.25.3.2.1.3.1";
    public const string PrtGeneralSerialNumber1 = "1.3.6.1.2.1.43.5.1.1.17.1";
    public const string HrDevicePrinter = "1.3.6.1.2.1.25.3.1.5";

    private static readonly string[] Oids =
    {
        SysDescr, SysObjectId, SysName, SysLocation, HrDeviceType1, HrDeviceDescr1, PrtGeneralSerialNumber1,
    };

    /// <summary>Known printer (and some IoT) vendors by enterprise number.</summary>
    public static readonly IReadOnlyDictionary<int, string> Enterprises = new Dictionary<int, string>
    {
        [11] = "HP",
        [236] = "Samsung",
        [253] = "Xerox",
        [367] = "Ricoh",
        [641] = "Lexmark",
        [1129] = "Toshiba",
        [1248] = "Epson",
        [1347] = "Kyocera",
        [1602] = "Canon",
        [2001] = "OKI",
        [2385] = "Sharp",
        [2435] = "Brother",
        [18334] = "Konica Minolta",
    };

    public static async Task<SnmpInfo?> GetAsync(
        IPAddress address, string community, TimeSpan timeout, CancellationToken cancellationToken)
    {
        // v2c first: a missing OID costs only that value, not the whole
        // answer as with v1 (noSuchName).
        var basic = new[] { SysDescr, SysObjectId, SysName };
        var values = await QueryAsync(address, community, 1, Oids, timeout, cancellationToken);
        if (values is { Count: 0 })
            // An answer with an error status: some agents refuse the whole
            // request over one OID they do not know - ask for less.
            values = await QueryAsync(address, community, 1, basic, timeout, cancellationToken);
        else if (values is null)
            // No answer to v2c at all: perhaps an agent that speaks only v1.
            values = await QueryAsync(address, community, 0, basic, timeout, cancellationToken);
        if (values is null || values.Count == 0)
            return null;

        string? Get(string oid) => values.TryGetValue(oid, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : null;
        return new SnmpInfo(
            Get(SysDescr), Get(SysObjectId), Get(SysName), Get(SysLocation),
            Get(HrDeviceType1), Get(HrDeviceDescr1), Get(PrtGeneralSerialNumber1));
    }

    private static async Task<Dictionary<string, string>?> QueryAsync(
        IPAddress address, string community, int version, IReadOnlyList<string> oids,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        int requestId = Random.Shared.Next(1, int.MaxValue);
        var packet = BuildGetRequest(version, community, requestId, oids);
        using var udp = new UdpClient(AddressFamily.InterNetwork);
        try
        {
            await udp.SendAsync(packet, new IPEndPoint(address, 161), cancellationToken);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);
            while (true)
            {
                var received = await udp.ReceiveAsync(cts.Token);
                if (!received.RemoteEndPoint.Address.Equals(address))
                    continue;
                Dictionary<string, string>? parsed;
                try
                {
                    parsed = ParseResponse(received.Buffer, requestId);
                }
                catch (Exception e) when (e is ArgumentException or IndexOutOfRangeException or OverflowException)
                {
                    parsed = null; // a malformed answer is no answer
                }
                if (parsed is not null)
                    return parsed;
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (SocketException)
        {
            return null; // ICMP port unreachable surfaces as ConnectionReset
        }
    }

    // ---- BER encoding ---------------------------------------------------

    internal static byte[] BuildGetRequest(int version, string community, int requestId, IReadOnlyList<string> oids)
    {
        var varbinds = new List<byte>();
        foreach (var oid in oids)
            varbinds.AddRange(Tlv(0x30, Concat(Tlv(0x06, EncodeOid(oid)), new byte[] { 0x05, 0x00 })));

        var pdu = Tlv(0xA0, Concat(
            Tlv(0x02, EncodeInteger(requestId)),
            Tlv(0x02, EncodeInteger(0)),
            Tlv(0x02, EncodeInteger(0)),
            Tlv(0x30, varbinds.ToArray())));

        return Tlv(0x30, Concat(
            Tlv(0x02, EncodeInteger(version)),
            Tlv(0x04, Encoding.ASCII.GetBytes(community)),
            pdu));
    }

    private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

    private static byte[] Tlv(byte tag, byte[] value)
    {
        var result = new List<byte> { tag };
        result.AddRange(EncodeLength(value.Length));
        result.AddRange(value);
        return result.ToArray();
    }

    private static byte[] EncodeLength(int length)
    {
        if (length < 0x80)
            return new[] { (byte)length };
        var bytes = new List<byte>();
        while (length > 0)
        {
            bytes.Insert(0, (byte)(length & 0xFF));
            length >>= 8;
        }
        bytes.Insert(0, (byte)(0x80 | bytes.Count));
        return bytes.ToArray();
    }

    private static byte[] EncodeInteger(int value)
    {
        var bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(bytes);
        // Shortest two's complement form.
        int skip = 0;
        while (skip < 3 && ((bytes[skip] == 0x00 && (bytes[skip + 1] & 0x80) == 0) ||
                            (bytes[skip] == 0xFF && (bytes[skip + 1] & 0x80) != 0)))
            skip++;
        return bytes[skip..];
    }

    internal static byte[] EncodeOid(string oid)
    {
        var parts = oid.Split('.').Select(uint.Parse).ToArray();
        var result = new List<byte> { (byte)(parts[0] * 40 + parts[1]) };
        foreach (var part in parts.Skip(2))
        {
            var chunk = new Stack<byte>();
            uint v = part;
            chunk.Push((byte)(v & 0x7F));
            v >>= 7;
            while (v > 0)
            {
                chunk.Push((byte)(0x80 | (v & 0x7F)));
                v >>= 7;
            }
            result.AddRange(chunk);
        }
        return result.ToArray();
    }

    internal static string DecodeOid(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return "";
        var sb = new StringBuilder();
        sb.Append(data[0] / 40).Append('.').Append(data[0] % 40);
        ulong value = 0;
        for (int i = 1; i < data.Length; i++)
        {
            value = (value << 7) | (uint)(data[i] & 0x7F);
            if ((data[i] & 0x80) == 0)
            {
                sb.Append('.').Append(value);
                value = 0;
            }
        }
        return sb.ToString();
    }

    // ---- BER decoding ---------------------------------------------------

    private ref struct Reader
    {
        private readonly ReadOnlySpan<byte> _data;
        private int _pos;

        public Reader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _pos = 0;
        }

        public bool AtEnd => _pos >= _data.Length;

        public bool TryRead(out byte tag, out ReadOnlySpan<byte> value)
        {
            tag = 0;
            value = default;
            if (_pos + 2 > _data.Length)
                return false;
            tag = _data[_pos++];
            int length = _data[_pos++];
            if ((length & 0x80) != 0)
            {
                int count = length & 0x7F;
                if (count is 0 or > 4 || count > _data.Length - _pos)
                    return false;
                length = 0;
                for (int i = 0; i < count; i++)
                    length = (length << 8) | _data[_pos++];
            }
            // Compared by subtraction: _pos + length can overflow.
            if (length < 0 || length > _data.Length - _pos)
                return false;
            value = _data.Slice(_pos, length);
            _pos += length;
            return true;
        }
    }

    private static long DecodeInteger(ReadOnlySpan<byte> data)
    {
        long value = data.Length > 0 && (data[0] & 0x80) != 0 ? -1 : 0;
        foreach (var b in data)
            value = (value << 8) | b;
        return value;
    }

    /// <summary>The varbinds of a GetResponse with this request id, or null.</summary>
    internal static Dictionary<string, string>? ParseResponse(ReadOnlySpan<byte> packet, int requestId)
    {
        var outer = new Reader(packet);
        if (!outer.TryRead(out var tag, out var message) || tag != 0x30)
            return null;

        var msg = new Reader(message);
        if (!msg.TryRead(out tag, out _) || tag != 0x02) return null;            // version
        if (!msg.TryRead(out tag, out _) || tag != 0x04) return null;            // community
        if (!msg.TryRead(out tag, out var pdu) || tag != 0xA2) return null;      // GetResponse

        var p = new Reader(pdu);
        if (!p.TryRead(out tag, out var id) || tag != 0x02 || DecodeInteger(id) != requestId) return null;
        if (!p.TryRead(out tag, out var error) || tag != 0x02) return null;
        if (!p.TryRead(out tag, out _) || tag != 0x02) return null;
        if (DecodeInteger(error) != 0) return new Dictionary<string, string>();
        if (!p.TryRead(out tag, out var list) || tag != 0x30) return null;

        var result = new Dictionary<string, string>();
        var binds = new Reader(list);
        while (!binds.AtEnd)
        {
            if (!binds.TryRead(out tag, out var bind) || tag != 0x30)
                break;
            var b = new Reader(bind);
            if (!b.TryRead(out tag, out var oidBytes) || tag != 0x06)
                continue;
            if (!b.TryRead(out var valueTag, out var value))
                continue;
            var oid = DecodeOid(oidBytes);
            switch (valueTag)
            {
                case 0x04: // OCTET STRING
                    result[oid] = DecodeText(value);
                    break;
                case 0x06: // OBJECT IDENTIFIER
                    result[oid] = DecodeOid(value);
                    break;
                case 0x02: // INTEGER
                case 0x41: // Counter32
                case 0x42: // Gauge32
                case 0x43: // TimeTicks
                    result[oid] = DecodeInteger(value).ToString();
                    break;
                // 0x80/0x81/0x82: noSuchObject, noSuchInstance, endOfMibView - skip.
            }
        }
        return result;
    }

    /// <summary>Printers mostly send ASCII, some UTF-8; drop trailing NULs and control bytes.</summary>
    private static string DecodeText(ReadOnlySpan<byte> value)
    {
        var text = Encoding.UTF8.GetString(value);
        return new string(text.Where(c => !char.IsControl(c) || c is '\n' or '\t').ToArray()).Trim();
    }
}
