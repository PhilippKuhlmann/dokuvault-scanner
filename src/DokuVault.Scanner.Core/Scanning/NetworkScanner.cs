using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace DokuVault.Scanner.Core.Scanning;

public sealed class ScanOptions
{
    public required IpRange Range { get; init; }
    public string SnmpCommunity { get; init; } = "public";
    public bool UseSnmp { get; init; } = true;
    public bool UseMulticast { get; init; } = true;
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromMilliseconds(1000);
    public TimeSpan PortTimeout { get; init; } = TimeSpan.FromMilliseconds(700);
    public int SweepConcurrency { get; init; } = 128;
    public int DetailConcurrency { get; init; } = 24;
}

public sealed record ScanProgress(int Done, int Total, string Phase);

/// <summary>
/// The scan, in three steps that overlap: a ping sweep over the range (which
/// also fills the ARP cache), the details of every host found (ports, names,
/// SNMP, web page), and alongside both mDNS and SSDP for the devices that
/// announce themselves. Found hosts are reported as soon as they answer and
/// again whenever more is known about them.
/// </summary>
public sealed class NetworkScanner
{
    private readonly OuiDatabase _oui;

    public NetworkScanner(OuiDatabase oui) => _oui = oui;

    /// <summary>A new host answered - called from a worker thread.</summary>
    public event Action<ScannedDevice>? DeviceFound;

    /// <summary>A known host has more details - called from a worker thread.</summary>
    public event Action<ScannedDevice>? DeviceUpdated;

    public async Task<IReadOnlyList<ScannedDevice>> ScanAsync(
        ScanOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        // Every task of the scan hangs on this token: whatever way the scan
        // ends, cancelling it releases workers and listeners.
        using var scanCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = scanCts.Token;
        var detailQueue = new BlockingCollection<ScannedDevice>();
        var detailWorkers = new List<Task>();
        try
        {
            return await ScanCoreAsync(options, progress, detailQueue, detailWorkers, token);
        }
        finally
        {
            scanCts.Cancel();
            if (!detailQueue.IsAddingCompleted)
                detailQueue.CompleteAdding();
            try
            {
                await Task.WhenAll(detailWorkers);
            }
            catch
            {
                // already reported through ScanCoreAsync, or cancelled
            }
            detailQueue.Dispose();
        }
    }

    private async Task<IReadOnlyList<ScannedDevice>> ScanCoreAsync(
        ScanOptions options, IProgress<ScanProgress>? progress, BlockingCollection<ScannedDevice> detailQueue,
        List<Task> detailWorkers, CancellationToken cancellationToken)
    {
        var devices = new ConcurrentDictionary<uint, ScannedDevice>();
        var locals = LocalNetworks.Discover();
        var localAddresses = locals.Select(l => l.LocalAddress).ToList();
        var gateways = locals.Where(l => l.Gateway is not null).Select(l => l.Gateway!).ToHashSet();
        // The neighbour cache only helps for addresses in a subnet of our own.
        bool onLink = locals.Any(l => l.Range.Contains(IpRange.ToAddress(options.Range.First)) &&
                                      l.Range.Contains(IpRange.ToAddress(options.Range.Last)));
        var multicastFrom = locals.Where(l => l.Range.Contains(IpRange.ToAddress(options.Range.First)))
            .Select(l => l.LocalAddress).DefaultIfEmpty(localAddresses.FirstOrDefault()).Where(a => a is not null)
            .Cast<IPAddress>().ToList();

        Task<Dictionary<IPAddress, List<MdnsService>>> mdnsTask = Task.FromResult(new Dictionary<IPAddress, List<MdnsService>>());
        Task<Dictionary<IPAddress, UpnpInfo>> ssdpTask = Task.FromResult(new Dictionary<IPAddress, UpnpInfo>());
        if (options.UseMulticast && multicastFrom.Count > 0)
        {
            mdnsTask = MdnsBrowser.BrowseAsync(multicastFrom, TimeSpan.FromSeconds(5), cancellationToken);
            ssdpTask = SsdpDiscovery.DiscoverAsync(multicastFrom, options.Range.Contains,
                TimeSpan.FromSeconds(4), cancellationToken);
        }

        ScannedDevice Register(IPAddress address, out bool isNew)
        {
            bool created = false;
            var device = devices.GetOrAdd(IpRange.ToUInt(address), _ =>
            {
                created = true;
                return new ScannedDevice
                {
                    Address = address,
                    IsGateway = gateways.Contains(address),
                    IsSelf = localAddresses.Contains(address),
                };
            });
            isNew = created;
            return device;
        }

        // ---- 1. sweep
        int total = (int)options.Range.Count;
        int done = 0;
        progress?.Report(new ScanProgress(0, total, "Suche Geräte …"));
        for (int i = 0; i < options.DetailConcurrency; i++)
        {
            detailWorkers.Add(Task.Run(async () =>
            {
                foreach (var device in detailQueue.GetConsumingEnumerable(cancellationToken))
                {
                    // One odd device must not end the scan for all others.
                    try
                    {
                        await DetailAsync(device, options, cancellationToken);
                    }
                    catch (Exception) when (!cancellationToken.IsCancellationRequested)
                    {
                        device.Suggestion = DeviceClassifier.Classify(device);
                        DeviceUpdated?.Invoke(device);
                    }
                }
            }, cancellationToken));
        }

        void Found(IPAddress address, long? pingMs)
        {
            var device = Register(address, out bool isNew);
            if (pingMs is not null)
                device.PingMs = pingMs;
            if (!isNew)
                return;
            device.Suggestion = DeviceClassifier.Classify(device);
            DeviceFound?.Invoke(device);
            detailQueue.Add(device, cancellationToken);
        }

        using (var gate = new SemaphoreSlim(options.SweepConcurrency))
        {
            var sweep = options.Range.Addresses().Where(IsHostAddress).Select(async address =>
            {
                await gate.WaitAsync(cancellationToken);
                try
                {
                    var ms = await PingAsync(address, options.PingTimeout);
                    // Off-link there is no ARP: a few common ports stand in
                    // for the ping a firewall dropped.
                    if (ms is null && !onLink && await AnyPortOpenAsync(address, new[] { 80, 443, 445, 9100 }, options.PortTimeout, cancellationToken))
                        ms = -1;
                    if (ms is not null)
                        Found(address, ms >= 0 ? ms : null);
                }
                finally
                {
                    gate.Release();
                    int now = Interlocked.Increment(ref done);
                    if (now % 8 == 0 || now == total)
                        progress?.Report(new ScanProgress(now, total, "Suche Geräte …"));
                }
            });
            await Task.WhenAll(sweep);
        }

        // ---- 2. neighbour cache: who answered ARP but not ping
        if (onLink)
        {
            var neighbors = NeighborTable.Read().Where(n => options.Range.Contains(n.Address)).ToList();
            foreach (var n in neighbors)
            {
                bool known = devices.ContainsKey(IpRange.ToUInt(n.Address));
                if (n.State is NeighborState.Reachable or NeighborState.Permanent)
                {
                    if (!known)
                        Found(n.Address, null);
                }
                else if (!known && n.State is NeighborState.Stale or NeighborState.Delay or NeighborState.Probe)
                {
                    // An old cache entry is no proof - ask again.
                    if (await ArpResolver.ResolveAsync(n.Address, cancellationToken) is not null)
                        Found(n.Address, null);
                }
            }
            FillMacs(devices);
            foreach (var self in devices.Values.Where(d => d.IsSelf && d.Mac is null))
                self.Mac = OwnMac(self.Address);
        }

        // ---- 3. multicast announcements - a failure there costs only them
        progress?.Report(new ScanProgress(total, total, "Lese Gerätedienste (mDNS, UPnP) …"));
        var mdns = await Quietly(mdnsTask, cancellationToken) ?? new Dictionary<IPAddress, List<MdnsService>>();
        var ssdp = await Quietly(ssdpTask, cancellationToken) ?? new Dictionary<IPAddress, UpnpInfo>();
        foreach (var (address, services) in mdns)
        {
            if (!options.Range.Contains(address))
                continue;
            var device = Register(address, out bool isNew);
            device.AddMdns(services);
            if (isNew)
            {
                device.Suggestion = DeviceClassifier.Classify(device);
                DeviceFound?.Invoke(device);
                detailQueue.Add(device, cancellationToken);
            }
        }
        foreach (var (address, upnp) in ssdp)
        {
            var device = Register(address, out bool isNew);
            device.Upnp = upnp;
            if (isNew)
            {
                device.Suggestion = DeviceClassifier.Classify(device);
                DeviceFound?.Invoke(device);
                detailQueue.Add(device, cancellationToken);
            }
        }

        detailQueue.CompleteAdding();
        progress?.Report(new ScanProgress(total, total, "Lese Details (Ports, SNMP, Web) …"));
        await Task.WhenAll(detailWorkers);

        // MACs of hosts that only turned up through multicast.
        if (onLink)
            FillMacs(devices);

        foreach (var device in devices.Values)
        {
            device.Suggestion = DeviceClassifier.Classify(device);
            DeviceUpdated?.Invoke(device);
        }
        progress?.Report(new ScanProgress(total, total, "Fertig"));
        return devices.Values.OrderBy(d => d.SortKey).ToList();
    }

    private void FillMacs(ConcurrentDictionary<uint, ScannedDevice> devices)
    {
        foreach (var n in NeighborTable.Read())
        {
            if (devices.TryGetValue(IpRange.ToUInt(n.Address), out var device) && device.Mac is null)
            {
                device.MacVendor = _oui.Lookup(n.Mac);
                device.Mac = n.Mac;
            }
        }
    }

    /// <summary>0.0.0.0 and the limited broadcast are no hosts; Ping refuses them.</summary>
    private static bool IsHostAddress(IPAddress address) =>
        !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.Broadcast);

    private static async Task<T?> Quietly<T>(Task<T> task, CancellationToken cancellationToken) where T : class
    {
        try
        {
            return await task;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private async Task DetailAsync(ScannedDevice device, ScanOptions options, CancellationToken cancellationToken)
    {
        var address = device.Address;
        var portsTask = OpenPortsAsync(address, DeviceClassifier.Ports, options.PortTimeout, cancellationToken);
        var dnsTask = ReverseDnsAsync(address, cancellationToken);
        var netbiosTask = NetBiosResolver.GetNameAsync(address, TimeSpan.FromMilliseconds(800), cancellationToken);
        var snmpTask = options.UseSnmp
            ? SnmpClient.GetAsync(address, options.SnmpCommunity, TimeSpan.FromMilliseconds(1200), cancellationToken)
            : Task.FromResult<SnmpInfo?>(null);
        await Task.WhenAll(portsTask, dnsTask, netbiosTask, snmpTask);

        device.OpenPorts = portsTask.Result;
        device.DnsName = dnsTask.Result;
        device.NetBiosName = netbiosTask.Result;
        device.Snmp = snmpTask.Result;

        using var probe = new HttpProbe();
        foreach (var (port, tls) in new[] { (80, false), (443, true), (8080, false), (8443, true) })
        {
            if (!device.OpenPorts.Contains(port))
                continue;
            var http = await probe.ProbeAsync(address, port, tls, cancellationToken);
            if (http is not null)
            {
                device.Http = http;
                break;
            }
        }

        device.Suggestion = DeviceClassifier.Classify(device);
        DeviceUpdated?.Invoke(device);
    }

    private static async Task<long?> PingAsync(IPAddress address, TimeSpan timeout)
    {
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, (int)timeout.TotalMilliseconds);
            return reply.Status == IPStatus.Success ? reply.RoundtripTime : null;
        }
        catch (Exception e) when (e is PingException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static async Task<List<int>> OpenPortsAsync(
        IPAddress address, IEnumerable<int> ports, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var checks = ports.Select(async p => await IsOpenAsync(address, p, timeout, cancellationToken) ? p : -1);
        return (await Task.WhenAll(checks)).Where(p => p > 0).ToList();
    }

    private static async Task<bool> AnyPortOpenAsync(
        IPAddress address, IEnumerable<int> ports, TimeSpan timeout, CancellationToken cancellationToken) =>
        (await OpenPortsAsync(address, ports, timeout, cancellationToken)).Count > 0;

    private static async Task<bool> IsOpenAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token);
            return true;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static async Task<string?> ReverseDnsAsync(IPAddress address, CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(2));
            var entry = await Dns.GetHostEntryAsync(address.ToString(), AddressFamily.InterNetwork, cts.Token);
            return string.IsNullOrWhiteSpace(entry.HostName) || entry.HostName == address.ToString() ? null : entry.HostName;
        }
        catch (Exception e) when (e is SocketException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static string? OwnMac(IPAddress address)
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(address)))
                {
                    var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                    return bytes.Length == 6 ? ArpResolver.Format(bytes) : null;
                }
            }
        }
        catch (NetworkInformationException)
        {
        }
        return null;
    }
}
