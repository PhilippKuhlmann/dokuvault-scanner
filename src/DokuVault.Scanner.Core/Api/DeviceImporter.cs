using System.Net;

namespace DokuVault.Scanner.Core.Api;

public sealed record ImportRequest(
    string Customer,
    string Type,
    IReadOnlyDictionary<string, object?> Values,
    IPAddress Address,
    int? NetworkId,
    string? IpLabel,
    bool Dhcp = false);

public enum ImportOutcome
{
    Created,
    /// <summary>The device exists, but its address could not be attached.</summary>
    CreatedWithoutIp,
    /// <summary>The address already belonged to the customer: the new device was taken back.</summary>
    AlreadyDocumented,
    Failed,
}

public sealed record ImportResult(
    ImportOutcome Outcome,
    int? Id,
    string Message,
    IReadOnlyDictionary<string, string[]>? FieldErrors = null,
    bool Unauthorized = false);

/// <summary>
/// Adds one scanned device: create it, then attach its address. The API has
/// no transaction over both steps, so a device whose address turns out to
/// be taken is moved back into the trash - otherwise every repeated import
/// would leave a duplicate.
/// </summary>
public sealed class DeviceImporter
{
    private readonly DokuVaultClient _client;

    public DeviceImporter(DokuVaultClient client) => _client = client;

    public async Task<ImportResult> ImportAsync(ImportRequest request, CancellationToken cancellationToken)
    {
        // Checked first: afterwards the device would exist without its address.
        if (request.Dhcp && request.NetworkId is null)
            return new ImportResult(ImportOutcome.Failed, null, "Für „per DHCP“ braucht DokuVault ein VLAN.");

        ObjectDetail created;
        try
        {
            created = await _client.CreateObjectAsync(request.Customer, request.Type, request.Values, cancellationToken);
        }
        catch (DokuVaultApiException e)
        {
            return new ImportResult(ImportOutcome.Failed, null, e.Message, e.FieldErrors, e.IsUnauthorized);
        }

        try
        {
            if (request.Dhcp)
                await _client.AddDhcpAddressAsync(request.Type, created.Id, request.NetworkId!.Value, request.IpLabel, cancellationToken);
            else
                await _client.AddIpAddressAsync(request.Type, created.Id, request.Address.ToString(), request.NetworkId,
                    request.IpLabel, cancellationToken);
            return new ImportResult(ImportOutcome.Created, created.Id, "Angelegt");
        }
        catch (DokuVaultApiException e) when (e.Status == HttpStatusCode.UnprocessableEntity && e.FieldErrors.ContainsKey("address"))
        {
            var why = e.FieldMessage("address");
            try
            {
                await _client.DeleteObjectAsync(request.Type, created.Id, CancellationToken.None);
                return new ImportResult(ImportOutcome.AlreadyDocumented, null, $"{why} Das neue Gerät wurde wieder entfernt.");
            }
            catch (DokuVaultApiException)
            {
                return new ImportResult(ImportOutcome.CreatedWithoutIp, created.Id,
                    $"{why} Das Gerät ist angelegt, aber ohne Adresse – bitte prüfen.");
            }
        }
        catch (DokuVaultApiException e)
        {
            // The device is there; better a device without address than none.
            return new ImportResult(ImportOutcome.CreatedWithoutIp, created.Id,
                $"Angelegt, aber die IP-Adresse fehlt: {e.Message}", e.FieldErrors);
        }
        catch (OperationCanceledException)
        {
            return new ImportResult(ImportOutcome.CreatedWithoutIp, created.Id, "Angelegt, IP-Adresse abgebrochen.");
        }
    }
}
