using System.Collections.ObjectModel;
using DokuVault.Scanner.Core;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Core.Scanning;
using DokuVault.Scanner.Infrastructure;

namespace DokuVault.Scanner.ViewModels;

/// <summary>
/// A DokuVault type a scanned device can become (see DeviceTypes). Equal by
/// value, so the ComboBox finds the row's choice in the list of the window.
/// </summary>
public sealed record TargetType(string? Key, string Label)
{
    public static readonly TargetType None = new(null, "nicht übernehmen");

    public static TargetType From(DeviceType type) => new(type.Key, type.Label);

    public override string ToString() => Label;
}

/// <summary>The VLAN an address is filed under; Key null = none.</summary>
public sealed record NetworkChoice(int? Id, string Label)
{
    public static readonly NetworkChoice None = new(null, "– kein VLAN –");
    public override string ToString() => Label;
}

public enum ImportState
{
    None,
    Running,
    Done,
    Failed,
}

public sealed class DeviceRowViewModel : ObservableObject
{
    private readonly Func<string, ObjectForm?> _form;
    private readonly Action<string> _needForm;
    private readonly Func<string, bool> _available;
    private readonly Dictionary<string, List<FieldViewModel>> _fieldsByType = new();
    private bool _isChecked;
    private TargetType _target = TargetType.None;
    private bool _targetChosen;
    private DocumentedAddress? _documented;
    private ImportState _importState;
    private string? _importMessage;
    private NetworkChoice _network = NetworkChoice.None;
    private bool _networkChosen;
    private string? _ipLabel;
    private bool _ipLabelTouched;
    private int? _createdId;
    private bool _locked;
    private bool _inDhcpRange;
    private bool _useDhcp;
    private bool _useDhcpChosen;
    private string? _networkError;

    /// <param name="form">The loaded form of a type, or null while it is not loaded.</param>
    /// <param name="needForm">Asks for a form that is not loaded yet; RebuildForType follows.</param>
    /// <param name="available">Whether the user may create this type at this customer (as far as known).</param>
    public DeviceRowViewModel(ScannedDevice device, Func<string, ObjectForm?> form, Action<string> needForm,
        Func<string, bool> available)
    {
        Device = device;
        _form = form;
        _needForm = needForm;
        _available = available;
        ApplySuggestion();
    }

    public ScannedDevice Device { get; }

    public ObservableCollection<FieldViewModel> Fields { get; } = new();

    // ---- what the scan found

    public string Address => Device.Address.ToString();
    public uint SortKey => Device.SortKey;
    public string? Mac => Device.Mac is null ? null : Device.MacRandomized ? Device.Mac + " (zufällig)" : Device.Mac;
    public string? Vendor => Device.Manufacturer;
    public string? Model => Device.Model;
    public string? FoundName => Device.BestName;
    public string? Hostname => Device.DnsName ?? Device.NetBiosName;
    public string Services => string.Join(" · ", new[] { Device.ServicesText, Device.PortsText }.Where(s => s.Length > 0));
    public string? PingText => Device.PingMs is long ms ? $"{ms} ms" : null;

    public string SuggestionText => DeviceTypes.KindLabel(Device.Suggestion.Kind);

    public int Confidence => Device.Suggestion.Confidence;
    public string Reasons => Device.Suggestion.Reasons.Count == 0 ? "Keine Merkmale erkannt." : string.Join("\n", Device.Suggestion.Reasons.Select(r => "• " + r));
    /// <summary>A type is chosen or suggested - the rest is phones, laptops and the unknown.</summary>
    public bool IsCandidate => Target.Key is not null;

    /// <summary>What the device said about itself, for the detail panel.</summary>
    public string Findings
    {
        get
        {
            var lines = new List<string>();
            void Add(string label, string? value)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    lines.Add($"{label}: {value}");
            }
            Add("DNS", Device.DnsName);
            Add("NetBIOS", Device.NetBiosName);
            Add("MAC-Hersteller", Device.MacVendor);
            Add("SNMP", Device.Snmp?.Description);
            Add("SNMP-Name", Device.Snmp?.Name);
            Add("SNMP-Standort", Device.Snmp?.Location);
            Add("Gerät (SNMP)", Device.Snmp?.DeviceDescription);
            Add("Web", Device.Http is { } h ? $"{h.Title ?? "(ohne Titel)"}  –  {h.Url}" : null);
            Add("Webserver", Device.Http?.Server);
            Add("UPnP", Device.Upnp is { } u ? string.Join(", ", new[] { u.FriendlyName, u.Manufacturer, u.ModelName, u.DeviceType }.Where(x => x is not null)) : null);
            foreach (var s in Device.Mdns)
                Add($"mDNS {ScannedDevice.ServiceLabel(s.ServiceType)}", s.InstanceName);
            Add("Offene Ports", Device.PortsText);
            Add("Antwortzeit", PingText);
            return lines.Count == 0 ? "Nur die Adresse antwortet." : string.Join("\n", lines);
        }
    }

    // ---- what the user makes of it

    public bool IsChecked
    {
        get => _isChecked;
        set => Set(ref _isChecked, value);
    }

    public TargetType Target
    {
        get => _target;
        set
        {
            // null is the ComboBox losing its list, not a choice.
            if (value is null || !Set(ref _target, value))
                return;
            _targetChosen = true;
            // Choosing a type is choosing to take it over.
            if (value.Key is not null && CanImport)
                IsChecked = true;
            else if (value.Key is null)
                IsChecked = false;
            RebuildFields();
            OnPropertyChanged(nameof(IsCandidate));
        }
    }

    public DocumentedAddress? Documented
    {
        get => _documented;
        set
        {
            if (!Set(ref _documented, value))
                return;
            if (value is not null && ImportState != ImportState.Done)
                IsChecked = false;
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(StatusKind));
            OnPropertyChanged(nameof(IsDocumented));
            OnPropertyChanged(nameof(CanImport));
            OnPropertyChanged(nameof(CanEdit));
        }
    }

    public bool IsDocumented => _documented is not null;

    /// <summary>The address lies in the DHCP range: the list and the detail panel show it.</summary>
    public bool InDhcpRange
    {
        get => _inDhcpRange;
        set
        {
            if (!Set(ref _inDhcpRange, value))
                return;
            // The range suggests "per DHCP"; a choice of the user stays.
            if (!_useDhcpChosen && Set(ref _useDhcp, value, nameof(UseDhcp)))
                OnPropertyChanged(nameof(DhcpWithoutMac));
        }
    }

    /// <summary>Documented "per DHCP": no address, only the VLAN.</summary>
    public bool UseDhcp
    {
        get => _useDhcp;
        set
        {
            if (!Set(ref _useDhcp, value))
                return;
            _useDhcpChosen = true;
            NetworkError = null;
            OnPropertyChanged(nameof(DhcpWithoutMac));
        }
    }

    /// <summary>Per DHCP only the MAC tells the device again in a later scan.</summary>
    public bool DhcpWithoutMac => _useDhcp && (Device.Mac is null || Device.MacRandomized);

    public string? NetworkError
    {
        get => _networkError;
        set => Set(ref _networkError, value);
    }

    public bool CanImport => !IsDocumented && ImportState != ImportState.Done;

    /// <summary>Set while an import holds this row: its values are taken already.</summary>
    public bool Locked
    {
        get => _locked;
        set
        {
            if (Set(ref _locked, value))
                OnPropertyChanged(nameof(CanEdit));
        }
    }

    public bool CanEdit => CanImport && !_locked;

    public string StatusText => ImportState switch
    {
        ImportState.Running => "wird übernommen …",
        ImportState.Done => "übernommen",
        ImportState.Failed => "Fehler",
        _ when _documented is { } d => d.Name is null ? "dokumentiert" : $"dokumentiert: {d.Name}",
        _ => "neu",
    };

    /// <summary>For the colour of the status: new, documented, running, done, failed.</summary>
    public string StatusKind => ImportState switch
    {
        ImportState.Running => "running",
        ImportState.Done => "done",
        ImportState.Failed => "failed",
        _ when _documented is not null => "documented",
        _ => "new",
    };

    public ImportState ImportState
    {
        get => _importState;
        set
        {
            if (!Set(ref _importState, value))
                return;
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(StatusKind));
            OnPropertyChanged(nameof(CanImport));
            OnPropertyChanged(nameof(CanEdit));
        }
    }

    public string? ImportMessage
    {
        get => _importMessage;
        set => Set(ref _importMessage, value);
    }

    public int? CreatedId
    {
        get => _createdId;
        set => Set(ref _createdId, value);
    }

    public NetworkChoice Network
    {
        get => _network;
        set
        {
            // null is the ComboBox losing its list (customer change), not a choice.
            if (value is not null && Set(ref _network, value))
            {
                _networkChosen = true;
                NetworkError = null;
            }
        }
    }

    public string? IpLabel
    {
        get => _ipLabel;
        set
        {
            if (Set(ref _ipLabel, value))
                _ipLabelTouched = true;
        }
    }

    /// <summary>The name that will be documented - shown in the list.</summary>
    public string? DisplayName => Field("name")?.Text is { Length: > 0 } n ? n : FoundName;

    public FieldViewModel? Field(string name) => Fields.FirstOrDefault(f => f.Name == name);

    // ---- updates

    /// <summary>The scan learnt more: refresh the columns and what was prefilled.</summary>
    public void Refresh()
    {
        if (!_targetChosen)
            ApplySuggestion();
        Prefill();
        if (!_ipLabelTouched && Device.Mac is not null && !Device.MacRandomized)
            Set(ref _ipLabel, $"MAC {Device.Mac}", nameof(IpLabel));
        foreach (var name in new[]
                 {
                     nameof(Mac), nameof(Vendor), nameof(Model), nameof(FoundName), nameof(Hostname), nameof(Services),
                     nameof(PingText), nameof(SuggestionText), nameof(Confidence), nameof(Reasons), nameof(Findings),
                     nameof(IsCandidate), nameof(DisplayName), nameof(DhcpWithoutMac),
                 })
            OnPropertyChanged(name);
    }

    /// <summary>The forms arrived (or the customer changed): fields anew.</summary>
    public void ResetFields()
    {
        _fieldsByType.Clear();
        RebuildFields();
    }

    /// <summary>Another customer: his VLANs, not the old choice.</summary>
    public void ResetNetwork()
    {
        _networkChosen = false;
        Set(ref _network, NetworkChoice.None, nameof(Network));
    }

    public void SuggestNetwork(NetworkChoice? choice)
    {
        if (_networkChosen)
            return;
        Set(ref _network, choice ?? NetworkChoice.None, nameof(Network));
    }

    public void ApplyDefaultSite(string? siteValue)
    {
        foreach (var fields in _fieldsByType.Values)
            fields.FirstOrDefault(f => f.Field.Kind == "standort")?.PrefillOption(siteValue);
    }

    public string? DefaultSite { get; set; }

    private void ApplySuggestion()
    {
        // Only a suggestion with some weight picks a type: "random MAC" alone
        // is a phone or laptop, nothing to document.
        var suggestion = Device.Suggestion;
        var type = suggestion.Confidence >= 30 ? DeviceTypes.ByKind(suggestion.Kind) : null;
        var target = type is not null && _available(type.Key) ? TargetType.From(type) : TargetType.None;
        if (target == _target)
            return;
        _target = target;
        OnPropertyChanged(nameof(Target));
        RebuildFields();
    }

    private void RebuildFields()
    {
        Fields.Clear();
        if (_target.Key is not { } type)
        {
            OnPropertyChanged(nameof(DisplayName));
            return;
        }
        var form = _form(type);
        if (form is null)
        {
            // Loaded on first use; RebuildForType comes back when it is there.
            // The load can also finish on the spot (answer from a cache, or
            // while this row is not yet in the list) - so ask once more.
            _needForm(type);
            form = _form(type);
            if (form is null)
            {
                OnPropertyChanged(nameof(DisplayName));
                return;
            }
        }

        if (!_fieldsByType.TryGetValue(type, out var fields))
        {
            fields = form.Fields.Select(f => new FieldViewModel(f)).Where(f => f.IsEditable).ToList();
            foreach (var f in fields)
            {
                if (form.Values?.TryGetValue(f.Name, out var value) == true)
                    f.ApplyDefault(value);
                f.PropertyChanged += (_, e) =>
                {
                    if (f.Name == "name" && e.PropertyName == nameof(FieldViewModel.Text))
                        OnPropertyChanged(nameof(DisplayName));
                };
            }
            _fieldsByType[type] = fields;
            // The name and model the user typed for one type carry over to the other.
            foreach (var other in _fieldsByType.Where(t => t.Key != type).SelectMany(t => t.Value).Where(o => o.Touched))
                fields.FirstOrDefault(f => f.Name == other.Name && f.Editor == other.Editor)?.CarryOver(other);
            fields.FirstOrDefault(f => f.Field.Kind == "standort")?.PrefillOption(DefaultSite);
        }
        foreach (var f in fields)
            Fields.Add(f);
        Prefill();
        OnPropertyChanged(nameof(DisplayName));
    }

    /// <summary>The form of this type arrived: the fields, if it is the one shown.</summary>
    public void RebuildForType(string type)
    {
        if (_target.Key == type)
            RebuildFields();
    }

    /// <summary>The user may not create this type here: back to "not taken over".</summary>
    public void TypeUnavailable(string type, string message)
    {
        _fieldsByType.Remove(type);
        if (_target.Key != type)
            return;
        Set(ref _target, TargetType.None, nameof(Target));
        IsChecked = false;
        Fields.Clear();
        ImportMessage = message;
        OnPropertyChanged(nameof(IsCandidate));
        OnPropertyChanged(nameof(DisplayName));
    }

    // Field names as in config/forms.php. What the scan knows goes where the
    // type has a field for it - the URL of an IoT device, the management page
    // of a firewall, the MAC of a phone (DECT and phones have no "name").
    private void Prefill()
    {
        Field("name")?.Prefill(FoundName ?? $"{_target.Label} {Address}");
        Field("manufacturer")?.Prefill(Device.Manufacturer);
        Field("model")?.Prefill(Device.Model);
        Field("serialNumber")?.Prefill(Device.SerialNumber);
        if (Device.WebUrl is { } web)
        {
            Field("url")?.Prefill(web);
            Field("management_url")?.Prefill(web);
        }
        if (Device.Mac is { } mac && !Device.MacRandomized)
            Field("mac")?.Prefill(mac);
    }
}
