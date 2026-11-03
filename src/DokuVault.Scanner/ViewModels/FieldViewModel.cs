using System.Globalization;
using System.Text.Json;
using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Infrastructure;

namespace DokuVault.Scanner.ViewModels;

/// <summary>
/// One field of the server's form. The form comes from DokuVault itself
/// (config/forms.php), so a field added there shows up here without a new
/// release of the app.
/// </summary>
public sealed class FieldViewModel : ObservableObject
{
    private string _text = "";
    private bool _flag;
    private FormOption? _option;
    private string? _error;

    public FieldViewModel(FormField field)
    {
        Field = field;
        Options = field.Options ?? Array.Empty<FormOption>();
    }

    public FormField Field { get; }
    public string Name => Field.Name;
    public string Label => Field.Required ? Field.Label + " *" : Field.Label;
    public string? Placeholder => Field.Placeholder;
    public IReadOnlyList<FormOption> Options { get; }

    /// <summary>Set once the user typed here - the scan then no longer overwrites it.</summary>
    public bool Touched { get; set; }

    /// <summary>How the field is drawn, see the DataTemplateSelector.</summary>
    public string Editor => Field.Kind switch
    {
        "schalter" => "bool",
        "standort" or "auswahl" when Options.Count > 0 && !Field.Multiple => "choice",
        "date" => "date",
        "mehrzeilig" => "multiline",
        // Not meaningful for a scanned device and not editable as text:
        // links to other objects, files, services.
        "host" or "verknuepfung" or "dienste" or "datei" or "optionen" => "skip",
        _ when Field.Secret => "skip",
        _ => "text",
    };

    public bool IsEditable => Editor != "skip";

    // The public setters are what the bindings call - anything set through
    // them counts as the user's input. The scan fills in through Prefill.

    public string Text
    {
        get => _text;
        set
        {
            if (Set(ref _text, value ?? ""))
            {
                Touched = true;
                Error = null;
            }
        }
    }

    public bool Flag
    {
        get => _flag;
        set
        {
            if (Set(ref _flag, value))
                Touched = true;
        }
    }

    public FormOption? Option
    {
        get => _option;
        set
        {
            if (Set(ref _option, value))
            {
                Touched = true;
                Error = null;
            }
        }
    }

    /// <summary>A date field as typed: TT.MM.JJJJ (also T.M.JJJJ or JJJJ-MM-TT); null when empty or unreadable.</summary>
    public DateTime? Date => ParseDate(Text);

    /// <summary>Typed into a date field, but no date.</summary>
    public bool IsInvalidDate => Editor == "date" && !string.IsNullOrWhiteSpace(Text) && Date is null;

    private static readonly string[] DateFormats = { "dd.MM.yyyy", "d.M.yyyy", "dd.MM.yy", "d.M.yy", "yyyy-MM-dd" };

    internal static DateTime? ParseDate(string? text) =>
        DateTime.TryParseExact(text?.Trim(), DateFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
            ? d
            : null;

    /// <summary>A value found by the scan; never over what the user typed.</summary>
    public void Prefill(string? value)
    {
        if (Touched || string.IsNullOrWhiteSpace(value))
            return;
        // Keep within the server's max:255.
        value = value.Trim();
        if (value.Length > 255)
            value = value[..255];
        if (Set(ref _text, value, nameof(Text)))
            Error = null;
    }

    /// <summary>What the user entered for another type of the same device - his input, kept as such.</summary>
    public void CarryOver(FieldViewModel other)
    {
        switch (Editor)
        {
            case "bool":
                Flag = other.Flag;
                break;
            case "choice":
                if (Options.FirstOrDefault(o => o.Value == other.Option?.Value) is { } option)
                    Option = option;
                break;
            default:
                if (!string.IsNullOrWhiteSpace(other.Text))
                    Text = other.Text;
                break;
        }
    }

    /// <summary>The site chosen at the bottom, for every device the user did not change.</summary>
    public void PrefillOption(string? value)
    {
        if (Touched)
            return;
        var option = Options.FirstOrDefault(o => o.Value == value);
        if (Set(ref _option, option, nameof(Option)))
            Error = null;
    }

    public string? Error
    {
        get => _error;
        set
        {
            if (Set(ref _error, value))
                OnPropertyChanged(nameof(HasError));
        }
    }

    public bool HasError => _error is not null;

    public bool IsEmpty => Editor switch
    {
        "bool" => false,
        "choice" => Option is null,
        _ => string.IsNullOrWhiteSpace(Text),
    };

    /// <summary>The value as the form API takes it: strings, bool for "schalter".</summary>
    public object? Value => Editor switch
    {
        "bool" => Flag,
        "choice" => Option?.Value ?? "",
        "date" => Date?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? Text.Trim(),
        _ => Text.Trim(),
    };

    /// <summary>The default the server put into the empty form - not a user input.</summary>
    public void ApplyDefault(JsonElement value)
    {
        switch (Editor)
        {
            case "bool":
                _flag = value.ValueKind == JsonValueKind.True;
                break;
            case "choice":
                var s = value.ValueKind == JsonValueKind.String ? value.GetString()
                    : value.ValueKind == JsonValueKind.Number ? value.GetRawText() : null;
                _option = Options.FirstOrDefault(o => o.Value == s);
                break;
            case "date":
                if (value.ValueKind == JsonValueKind.String && ParseDate(value.GetString()) is { } d)
                    _text = d.ToString("dd.MM.yyyy", CultureInfo.InvariantCulture);
                break;
            default:
                if (value.ValueKind == JsonValueKind.String)
                    _text = value.GetString() ?? "";
                else if (value.ValueKind == JsonValueKind.Number)
                    _text = value.GetRawText();
                break;
        }
    }
}
