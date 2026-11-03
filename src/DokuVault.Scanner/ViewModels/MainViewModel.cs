using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using DokuVault.Scanner.Core;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Core.Scanning;
using DokuVault.Scanner.Infrastructure;

namespace DokuVault.Scanner.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    // Only for the manufacturer lists of the IEEE; devices are asked by the scanner's own clients.
    private readonly HttpClient _ouiHttp = new() { Timeout = TimeSpan.FromMinutes(3) };
    private readonly Dictionary<string, ObjectForm> _forms = new();
    private readonly Dictionary<string, Task> _formLoads = new();
    private readonly HashSet<string> _unavailable = new();
    private readonly Dictionary<uint, DeviceRowViewModel> _rowsByAddress = new();
    private Dictionary<string, DocumentedAddress> _documented = new();
    private List<NetworkEntry> _networkEntries = new();
    private List<NetworkEntry> _coveredNetworks = new();
    private bool _networksReadable;
    private bool _customerLoaded;
    private OuiDatabase _oui = OuiDatabase.Empty;
    private Task? _ouiTask;
    private CancellationTokenSource? _scanCts;
    private CancellationTokenSource? _customerCts;

    private Customer? _customer;
    private FormOption? _defaultSite;
    private DeviceRowViewModel? _selected;
    private string _rangeText = "";
    private LocalNetwork? _localNetwork;
    private bool _isScanning;
    private bool _isImporting;
    private bool _isLoadingCustomer;
    private int _progressDone;
    private int _progressTotal = 1;
    private string _status = "Bereit.";
    private string? _warning;
    private bool _hideDocumented;
    private bool _onlyCandidates;
    private string _filter = "";

    public MainViewModel(DokuVaultClient client, User user, AppSettings settings)
    {
        Client = client;
        User = user;
        _settings = settings;
        _hideDocumented = settings.HideDocumented;
        SnmpCommunity = settings.SnmpCommunity;
        UseSnmp = settings.UseSnmp;

        RowsView = CollectionViewSource.GetDefaultView(Rows);
        RowsView.Filter = o => o is DeviceRowViewModel r && Matches(r);
        RowsView.SortDescriptions.Add(new SortDescription(nameof(DeviceRowViewModel.SortKey), ListSortDirection.Ascending));

        ScanCommand = new AsyncCommand(ScanAsync, () => !IsScanning && !IsImporting);
        CancelCommand = new RelayCommand(() => _scanCts?.Cancel(), () => IsScanning);
        // Not while a customer loads: forms, sites and VLANs would be the old customer's.
        ImportCommand = new AsyncCommand(ImportAsync,
            () => !IsBusy && _customerLoaded && Customer is not null && ImportCount > 0);
        RefreshDocumentedCommand = new AsyncCommand(() => LoadCustomerAsync(Customer),
            () => Customer is not null && !IsImporting && !IsLoadingCustomer);
        CheckAllCommand = new RelayCommand(() => SetChecked(true));
        CheckNoneCommand = new RelayCommand(() => SetChecked(false));
        OpenInBrowserCommand = new RelayCommand(OpenInBrowser, p => p is DeviceRowViewModel { CreatedId: not null } || Customer is not null);
        UpdateVendorsCommand = new AsyncCommand(() => LoadVendorsAsync(force: true));

        foreach (var n in LocalNetworks.Discover())
            LocalNetworkChoices.Add(n);
        var initial = LocalNetworkChoices.FirstOrDefault();
        _localNetwork = initial;
        _rangeText = settings.Range ?? initial?.SuggestedRange.ToString() ?? "192.168.1.0/24";

        _ouiTask = LoadVendorsAsync(force: false);
    }

    public DokuVaultClient Client { get; }
    public User User { get; }
    public string UserText => $"{User.Name} · {Client.ServerUrl.Host}";

    /// <summary>Raised when the server no longer accepts the token.</summary>
    public event Action? SignedOut;

    public ObservableCollection<Customer> Customers { get; } = new();
    public ObservableCollection<FormOption> Sites { get; } = new();
    public ObservableCollection<NetworkChoice> NetworkChoices { get; } = new() { NetworkChoice.None };
    public ObservableCollection<LocalNetwork> LocalNetworkChoices { get; } = new();
    public ObservableCollection<DeviceRowViewModel> Rows { get; } = new();
    public ICollectionView RowsView { get; }
    /// <summary>"Not taken over" and every type the user may create at this customer, as far as known.</summary>
    public ObservableCollection<TargetType> TargetTypes { get; } =
        new(new[] { TargetType.None }.Concat(DeviceTypes.All.Select(TargetType.From)));

    public ICommand ScanCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ImportCommand { get; }
    public ICommand RefreshDocumentedCommand { get; }
    public ICommand CheckAllCommand { get; }
    public ICommand CheckNoneCommand { get; }
    public ICommand OpenInBrowserCommand { get; }
    public ICommand UpdateVendorsCommand { get; }

    public string SnmpCommunity { get; set; }
    public bool UseSnmp { get; set; }

    public Customer? Customer
    {
        get => _customer;
        set
        {
            if (Set(ref _customer, value))
                _ = LoadCustomerAsync(value);
        }
    }

    public FormOption? DefaultSite
    {
        get => _defaultSite;
        set
        {
            if (!Set(ref _defaultSite, value))
                return;
            if (Customer is not null && value is not null)
                _settings.Sites[Customer.Slug] = value.Value;
            foreach (var row in Rows)
            {
                row.DefaultSite = value?.Value;
                row.ApplyDefaultSite(value?.Value);
            }
            SuggestNetworks();
        }
    }

    public DeviceRowViewModel? Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

    public LocalNetwork? LocalNetwork
    {
        get => _localNetwork;
        set
        {
            if (Set(ref _localNetwork, value) && value is not null)
                RangeText = value.SuggestedRange.ToString();
        }
    }

    public string RangeText
    {
        get => _rangeText;
        set => Set(ref _rangeText, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        private set
        {
            if (Set(ref _isScanning, value))
                OnPropertyChanged(nameof(IsBusy));
        }
    }

    public bool IsImporting
    {
        get => _isImporting;
        private set
        {
            if (Set(ref _isImporting, value))
                OnPropertyChanged(nameof(IsBusy));
        }
    }

    public bool IsLoadingCustomer
    {
        get => _isLoadingCustomer;
        private set
        {
            if (Set(ref _isLoadingCustomer, value))
            {
                OnPropertyChanged(nameof(IsBusy));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool IsBusy => IsScanning || IsImporting || IsLoadingCustomer;

    public int ProgressDone
    {
        get => _progressDone;
        private set => Set(ref _progressDone, value);
    }

    public int ProgressTotal
    {
        get => _progressTotal;
        private set => Set(ref _progressTotal, value);
    }

    public string Status
    {
        get => _status;
        private set => Set(ref _status, value);
    }

    public string? Warning
    {
        get => _warning;
        private set
        {
            if (Set(ref _warning, value))
                OnPropertyChanged(nameof(HasWarning));
        }
    }

    public bool HasWarning => !string.IsNullOrEmpty(_warning);

    public bool HideDocumented
    {
        get => _hideDocumented;
        set
        {
            if (Set(ref _hideDocumented, value))
            {
                _settings.HideDocumented = value;
                RowsView.Refresh();
            }
        }
    }

    public bool OnlyCandidates
    {
        get => _onlyCandidates;
        set
        {
            if (Set(ref _onlyCandidates, value))
                RowsView.Refresh();
        }
    }

    public string Filter
    {
        get => _filter;
        set
        {
            if (Set(ref _filter, value ?? ""))
                RowsView.Refresh();
        }
    }

    public int ImportCount => Rows.Count(r => r.IsChecked && r.Target.Key is not null && r.CanImport);

    public string ImportButtonText => ImportCount switch
    {
        0 => "Nichts ausgewählt",
        1 => "1 Gerät in DokuVault übernehmen",
        var n => $"{n} Geräte in DokuVault übernehmen",
    };

    public string CountText
    {
        get
        {
            int total = Rows.Count, documented = Rows.Count(r => r.IsDocumented);
            if (total == 0)
                return "Noch kein Scan.";
            return $"{total} Geräte gefunden · {documented} schon dokumentiert · {total - documented} neu";
        }
    }

    // ---- start

    public async Task InitializeAsync()
    {
        try
        {
            var customers = await Client.CustomersAsync(CancellationToken.None);
            Customers.Clear();
            foreach (var c in customers)
                Customers.Add(c);
            Customer = Customers.FirstOrDefault(c => c.Slug == _settings.Customer)
                       ?? (User.Customer is { } own ? Customers.FirstOrDefault(c => c.Slug == own.Slug) : null)
                       ?? (Customers.Count == 1 ? Customers[0] : null);
            if (Customers.Count == 0)
                Warning = "Ihr Zugang sieht keinen Kunden.";
        }
        catch (DokuVaultApiException e)
        {
            HandleApiError(e);
        }
    }

    private async Task LoadCustomerAsync(Customer? customer)
    {
        _customerCts?.Cancel();
        var cts = _customerCts = new CancellationTokenSource();
        var token = cts.Token;
        // Nothing of the previous customer may survive: not its forms, sites,
        // VLANs or documented addresses - and until the new one is complete,
        // nothing can be imported.
        _customerLoaded = false;
        _networksReadable = false;
        _forms.Clear();
        _formLoads.Clear();
        _unavailable.Clear();
        RestoreTargetTypes();
        Sites.Clear();
        _documented = new Dictionary<string, DocumentedAddress>();
        _networkEntries = new List<NetworkEntry>();
        _coveredNetworks = new List<NetworkEntry>();
        foreach (var row in Rows)
        {
            row.ResetNetwork();
            row.ResetFields();
            if (row.ImportState != ImportState.Done)
                row.Documented = null;
        }
        NetworkChoices.Clear();
        NetworkChoices.Add(NetworkChoice.None);
        Warning = null;
        UpdateCounts();
        if (customer is null)
            return;
        _settings.Customer = customer.Slug;
        SettingsStore.Save(_settings);

        IsLoadingCustomer = true;
        Status = $"Lade {customer.Name} …";
        var warnings = new List<string>();
        try
        {
            // The forms the rows need now, plus the two most common types -
            // the rest is loaded when a row picks it (19 at once would run
            // into the server's 60 requests a minute).
            EnsureForm("iotdevice");
            EnsureForm("printer");
            await Task.WhenAll(_formLoads.Values.ToList());
            token.ThrowIfCancellationRequested();
            if (_forms.Count > 0 && Sites.Count == 0)
                warnings.Add("Der Kunde hat noch keinen Standort – ohne Standort lässt sich kein Gerät anlegen.");
            else if (_forms.Count == 0 && _unavailable.Count > 0)
                warnings.Add("Sie dürfen bei diesem Kunden die gängigen Gerätetypen nicht anlegen.");

            try
            {
                var plans = await Client.DocumentedAddressesAsync(customer.Slug, token);
                token.ThrowIfCancellationRequested();
                _networksReadable = true;
                _networkEntries = plans.Networks.ToList();
                _coveredNetworks = plans.Covered.ToList();
                _documented = plans.Addresses
                    .GroupBy(a => a.Address)
                    .ToDictionary(g => g.Key, g => g.FirstOrDefault(a => a.Name is not null) ?? g.First());
                foreach (var n in plans.Networks.Where(n => n.Error is null))
                    NetworkChoices.Add(new NetworkChoice(n.Id, n.Site is null ? n.Name : $"{n.Name} ({n.Site.Name})"));
                warnings.AddRange(plans.Warnings);
            }
            catch (DokuVaultApiException e) when (e.Status == HttpStatusCode.Forbidden)
            {
                warnings.Add("Ohne Recht auf VLANs wird jede Adresse vor dem Anlegen einzeln gesucht.");
            }

            foreach (var row in Rows)
            {
                row.ResetFields();
                row.DefaultSite = DefaultSite?.Value;
                row.ApplyDefaultSite(DefaultSite?.Value);
                if (row.ImportState != ImportState.Done)
                    row.Documented = _documented.GetValueOrDefault(row.Address);
            }
            SuggestNetworks();
            _customerLoaded = true;
            Status = $"{customer.Name}: {_documented.Count} Adressen dokumentiert.";
            Warning = warnings.Count == 0 ? null : string.Join("\n", warnings);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return;
        }
        catch (DokuVaultApiException e)
        {
            // Stays not loaded: the import remains off until "↻" succeeds.
            HandleApiError(e);
        }
        finally
        {
            if (_customerCts == cts)
                IsLoadingCustomer = false;
        }
        UpdateCounts();
        RowsView.Refresh();
    }

    // ---- forms, loaded on first use

    /// <summary>Starts loading the form of a type unless it is loaded, loading or not allowed.</summary>
    private void EnsureForm(string type)
    {
        if (Customer is not { } customer || _customerCts is not { } cts ||
            _forms.ContainsKey(type) || _formLoads.ContainsKey(type) || _unavailable.Contains(type))
            return;
        _formLoads[type] = LoadFormAsync(customer, type, cts.Token);
    }

    private async Task LoadFormAsync(Customer customer, string type, CancellationToken token)
    {
        try
        {
            var form = await Client.CreateFormAsync(customer.Slug, type, token);
            if (token.IsCancellationRequested || Customer != customer)
                return;
            _forms[type] = form;
            if (Sites.Count == 0 && form.Sites.Count > 0)
                FillSites(customer, form.Sites);
            foreach (var row in Rows)
                row.RebuildForType(type);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (DokuVaultApiException e) when (e.Status is HttpStatusCode.Forbidden or HttpStatusCode.NotFound)
        {
            if (!token.IsCancellationRequested)
                MarkUnavailable(type);
        }
        catch (DokuVaultApiException e)
        {
            if (token.IsCancellationRequested)
                return;
            // Not cached: the next row that picks the type tries again.
            _formLoads.Remove(type);
            if (e.IsUnauthorized)
                SignedOut?.Invoke();
            else
                Warning = $"Formular „{DeviceTypes.ByKey(type)?.Label ?? type}“ nicht geladen: {e.Message}";
        }
    }

    private void FillSites(Customer customer, IReadOnlyList<FormOption> sites)
    {
        foreach (var s in sites)
            Sites.Add(s);
        _defaultSite = null;
        DefaultSite = sites.FirstOrDefault(s => _settings.Sites.TryGetValue(customer.Slug, out var v) && v == s.Value)
                      ?? (sites.Count == 1 ? sites[0] : null);
        OnPropertyChanged(nameof(DefaultSite));
    }

    /// <summary>403 on the form: the user may not create this type here.</summary>
    private void MarkUnavailable(string type)
    {
        _unavailable.Add(type);
        var label = DeviceTypes.ByKey(type)?.Label ?? type;
        // The rows first, so no ComboBox loses its selected item to the list.
        foreach (var row in Rows)
            row.TypeUnavailable(type, $"Sie dürfen bei diesem Kunden kein Gerät vom Typ „{label}“ anlegen.");
        if (TargetTypes.FirstOrDefault(t => t.Key == type) is { } item)
            TargetTypes.Remove(item);
        UpdateCounts();
    }

    /// <summary>A new customer: every type again, in catalogue order, without clearing the list.</summary>
    private void RestoreTargetTypes()
    {
        int index = 1;
        foreach (var type in DeviceTypes.All)
        {
            var item = TargetType.From(type);
            if (!TargetTypes.Contains(item))
                TargetTypes.Insert(index, item);
            index++;
        }
    }

    /// <summary>
    /// Whether "not in the IP plans" means "free" for this address: only
    /// inside a VLAN whose plan was read completely.
    /// </summary>
    private bool IsCoveredByPlans(IPAddress address) =>
        _networksReadable && DokuVaultClient.MatchNetwork(_coveredNetworks, address, null) is not null;

    // ---- scan

    private async Task LoadVendorsAsync(bool force)
    {
        if (force)
            Status = "Lade die Herstellerliste der IEEE …";
        var (db, problem) = await OuiDatabase.LoadAsync(_ouiHttp, force, CancellationToken.None);
        _oui = db;
        if (force)
            Status = problem ?? $"Herstellerliste aktualisiert ({db.Count:N0} Einträge).";
        else if (problem is not null && db.Count == 0)
            Status = problem;
    }

    private async Task ScanAsync()
    {
        if (!IpRange.TryParse(RangeText, out var range, out var error))
        {
            Warning = error;
            return;
        }
        _settings.Range = RangeText;
        _settings.SnmpCommunity = SnmpCommunity;
        _settings.UseSnmp = UseSnmp;
        SettingsStore.Save(_settings);

        if (_ouiTask is not null)
            await _ouiTask;

        // A new scan keeps rows already taken over, so their result stays visible.
        foreach (var row in Rows.Where(r => r.ImportState != ImportState.Done).ToList())
        {
            Rows.Remove(row);
            _rowsByAddress.Remove(row.SortKey);
        }
        Selected = null;
        IsScanning = true;
        Warning = null;
        _scanCts = new CancellationTokenSource();
        var dispatcher = Application.Current.Dispatcher;
        var scanner = new NetworkScanner(_oui);
        scanner.DeviceFound += d => dispatcher.BeginInvoke(() => AddOrUpdate(d));
        scanner.DeviceUpdated += d => dispatcher.BeginInvoke(() => AddOrUpdate(d));
        var progress = new Progress<ScanProgress>(p =>
        {
            ProgressTotal = Math.Max(1, p.Total);
            ProgressDone = p.Done;
            Status = p.Phase == "Fertig" ? Status : $"{p.Phase} {p.Done}/{p.Total}";
        });

        var watch = Stopwatch.StartNew();
        try
        {
            await Task.Run(() => scanner.ScanAsync(new ScanOptions
            {
                Range = range!,
                SnmpCommunity = string.IsNullOrWhiteSpace(SnmpCommunity) ? "public" : SnmpCommunity.Trim(),
                UseSnmp = UseSnmp,
            }, progress, _scanCts.Token));
            Status = $"Scan von {range} fertig nach {watch.Elapsed.TotalSeconds:0} s.";
        }
        catch (OperationCanceledException)
        {
            Status = "Scan abgebrochen.";
        }
        finally
        {
            IsScanning = false;
            ProgressDone = ProgressTotal;
            _scanCts.Dispose();
            _scanCts = null;
        }
        // Events queued by the scan threads land before this point is reached
        // again only through the dispatcher - flush them, then count.
        await dispatcher.InvokeAsync(() => { }, System.Windows.Threading.DispatcherPriority.Background);
        UpdateCounts();
        RowsView.Refresh();
    }

    private void AddOrUpdate(ScannedDevice device)
    {
        if (!_rowsByAddress.TryGetValue(device.SortKey, out var row))
        {
            row = new DeviceRowViewModel(device, type => _forms.GetValueOrDefault(type), EnsureForm,
                type => !_unavailable.Contains(type))
            {
                DefaultSite = DefaultSite?.Value,
            };
            row.ApplyDefaultSite(DefaultSite?.Value);
            row.Documented = _documented.GetValueOrDefault(row.Address);
            row.PropertyChanged += RowChanged;
            _rowsByAddress[device.SortKey] = row;
            Rows.Add(row);
            SuggestNetwork(row);
        }
        else if (!ReferenceEquals(row.Device, device))
        {
            return; // a row of an earlier scan, already taken over
        }
        row.Refresh();
        UpdateCounts();
    }

    private void RowChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(DeviceRowViewModel.IsChecked) or nameof(DeviceRowViewModel.Target)
            or nameof(DeviceRowViewModel.CanImport))
            UpdateCounts();
    }

    private void UpdateCounts()
    {
        OnPropertyChanged(nameof(ImportCount));
        OnPropertyChanged(nameof(ImportButtonText));
        OnPropertyChanged(nameof(CountText));
        CommandManager.InvalidateRequerySuggested();
    }

    private bool Matches(DeviceRowViewModel row)
    {
        if (HideDocumented && row.IsDocumented && row.ImportState != ImportState.Done)
            return false;
        if (OnlyCandidates && !row.IsCandidate)
            return false;
        if (Filter.Length == 0)
            return true;
        return new[] { row.Address, row.DisplayName, row.Vendor, row.Model, row.Mac, row.Hostname, row.Services }
            .Any(v => v?.Contains(Filter, StringComparison.OrdinalIgnoreCase) == true);
    }

    private void SetChecked(bool value)
    {
        foreach (var row in RowsView.Cast<DeviceRowViewModel>())
            row.IsChecked = value && row.Target.Key is not null && row.CanImport;
    }

    private void SuggestNetworks()
    {
        foreach (var row in Rows)
            SuggestNetwork(row);
    }

    private void SuggestNetwork(DeviceRowViewModel row)
    {
        int? site = int.TryParse(DefaultSite?.Value, out var s) ? s : null;
        var match = DokuVaultClient.MatchNetwork(_networkEntries, row.Device.Address, site);
        row.SuggestNetwork(match is null ? null : NetworkChoices.FirstOrDefault(c => c.Id == match.Id));
    }

    // ---- import

    private sealed record ImportJob(DeviceRowViewModel Row, string Type, Dictionary<string, object?> Values, int? NetworkId, string? Label);

    private async Task ImportAsync()
    {
        if (Customer is not { } customer || !_customerLoaded)
            return;
        var rows = Rows.Where(r => r.IsChecked && r.Target.Key is not null && r.CanImport).OrderBy(r => r.SortKey).ToList();
        if (rows.Count == 0)
            return;

        // Required fields first, so nothing is created half-way through a list.
        var incomplete = rows.Where(r => !Validate(r)).ToList();
        if (incomplete.Count > 0)
        {
            Selected = incomplete[0];
            Warning = incomplete.Count == 1
                ? $"Bei {incomplete[0].Address} fehlen Pflichtangaben."
                : $"Bei {incomplete.Count} Geräten fehlen Pflichtangaben (z. B. {incomplete[0].Address}).";
            return;
        }

        // What is imported is fixed here; the rows stay locked until done,
        // so a change in the list cannot reach a half-finished import.
        var jobs = rows.Select(r => new ImportJob(r, r.Target.Key!, r.Fields.ToDictionary(f => f.Name, f => f.Value),
            r.Network.Id, string.IsNullOrWhiteSpace(r.IpLabel) ? null : r.IpLabel.Trim())).ToList();
        foreach (var job in jobs)
            job.Row.Locked = true;

        IsImporting = true;
        Warning = null;
        var importer = new DeviceImporter(Client);
        int created = 0, skipped = 0, failed = 0;
        bool signedOut = false;
        try
        {
            foreach (var job in jobs)
            {
                var row = job.Row;
                Status = $"Übernehme {row.Address} ({created + skipped + failed + 1}/{jobs.Count}) …";
                row.ImportState = ImportState.Running;
                row.ImportMessage = null;
                try
                {
                    // Outside the completely read IP plans "not listed" proves
                    // nothing - ask the server about this one address.
                    if (!IsCoveredByPlans(row.Device.Address))
                    {
                        DocumentedAddress? found = null;
                        try
                        {
                            found = await Client.FindDocumentedAsync(customer.Slug, row.Address, CancellationToken.None);
                        }
                        catch (DokuVaultApiException e) when (!e.IsUnauthorized)
                        {
                            // the POST below has the final say anyway
                        }
                        if (found is not null)
                        {
                            _documented[row.Address] = found;
                            row.ImportState = ImportState.None;
                            row.Documented = found;
                            row.ImportMessage = "Diese Adresse ist schon dokumentiert.";
                            skipped++;
                            continue;
                        }
                    }

                    var result = await importer.ImportAsync(new ImportRequest(
                        customer.Slug, job.Type, job.Values, row.Device.Address, job.NetworkId, job.Label), CancellationToken.None);

                    row.ImportMessage = result.Message;
                    switch (result.Outcome)
                    {
                        case ImportOutcome.Created:
                        case ImportOutcome.CreatedWithoutIp:
                            row.CreatedId = result.Id;
                            row.ImportState = ImportState.Done;
                            row.IsChecked = false;
                            var name = job.Values.GetValueOrDefault("name") as string ?? row.DisplayName;
                            _documented[row.Address] = new DocumentedAddress(row.Address, name, job.Type, result.Id, job.NetworkId, null);
                            row.Documented = _documented[row.Address];
                            created++;
                            break;
                        case ImportOutcome.AlreadyDocumented:
                            row.ImportState = ImportState.None;
                            row.Documented = new DocumentedAddress(row.Address, null, null, null, null, null);
                            skipped++;
                            break;
                        default:
                            row.ImportState = ImportState.Failed;
                            foreach (var (field, messages) in result.FieldErrors ?? new Dictionary<string, string[]>())
                                if (row.Field(field) is { } f && messages.Length > 0)
                                    f.Error = messages[0];
                            failed++;
                            if (result.Unauthorized)
                                signedOut = true;
                            break;
                    }
                }
                catch (DokuVaultApiException e) when (e.IsUnauthorized)
                {
                    row.ImportState = ImportState.Failed;
                    row.ImportMessage = e.Message;
                    failed++;
                    signedOut = true;
                }
                catch (Exception e)
                {
                    // A row never stays "running".
                    row.ImportState = ImportState.Failed;
                    row.ImportMessage = e.Message;
                    failed++;
                }
                if (signedOut)
                    break;
            }
        }
        finally
        {
            foreach (var job in jobs)
            {
                job.Row.Locked = false;
                if (job.Row.ImportState == ImportState.Running)
                    job.Row.ImportState = ImportState.None;
            }
            IsImporting = false;
            UpdateCounts();
            RowsView.Refresh();
        }

        if (signedOut)
        {
            SignedOut?.Invoke();
            return;
        }
        Status = $"Fertig: {created} angelegt" +
                 (skipped > 0 ? $", {skipped} waren schon dokumentiert" : "") +
                 (failed > 0 ? $", {failed} mit Fehler" : "") + ".";
        if (failed > 0)
        {
            Selected = rows.FirstOrDefault(r => r.ImportState == ImportState.Failed);
            Warning = "Nicht alle Geräte wurden übernommen – Details stehen beim jeweiligen Gerät.";
        }
    }

    private static bool Validate(DeviceRowViewModel row)
    {
        bool ok = row.Fields.Count > 0;
        foreach (var f in row.Fields)
        {
            f.Error = null;
            if (f.Field.Required && f.IsEmpty)
            {
                f.Error = "Pflichtfeld";
                ok = false;
            }
            else if (f.IsInvalidDate)
            {
                f.Error = "Bitte als Datum TT.MM.JJJJ";
                ok = false;
            }
            // Only "url" (IoT device) is "nullable|url" on the server; the
            // management_url of a firewall is free text there.
            else if (f.Name == "url" && !f.IsEmpty &&
                     !Uri.TryCreate(f.Text.Trim(), UriKind.Absolute, out _))
            {
                f.Error = "Bitte eine vollständige Adresse mit http:// oder https://";
                ok = false;
            }
        }
        if (!ok && row.Fields.Count == 0)
            row.ImportMessage = $"Das Formular für „{row.Target.Label}“ ist noch nicht geladen – bitte gleich noch einmal.";
        return ok;
    }

    private void OpenInBrowser(object? parameter)
    {
        if (Customer is null)
            return;
        var type = parameter is DeviceRowViewModel { Target.Key: { } t } ? t : "iotdevice";
        try
        {
            Process.Start(new ProcessStartInfo(Client.BrowserListUrl(Customer.Slug, type).ToString()) { UseShellExecute = true });
        }
        catch (Win32Exception)
        {
        }
    }

    private void HandleApiError(DokuVaultApiException e)
    {
        if (e.IsUnauthorized)
        {
            SignedOut?.Invoke();
            return;
        }
        Warning = e.Message;
        Status = "Fehler beim Laden.";
    }

    public void SaveSettings()
    {
        _settings.Range = RangeText;
        _settings.SnmpCommunity = SnmpCommunity;
        _settings.UseSnmp = UseSnmp;
        SettingsStore.Save(_settings);
    }

    public void CancelAll()
    {
        _scanCts?.Cancel();
        _customerCts?.Cancel();
    }
}
