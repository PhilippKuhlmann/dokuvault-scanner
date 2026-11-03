using DokuVault.Scanner.Core.Api;
using DokuVault.Scanner.Infrastructure;

namespace DokuVault.Scanner.ViewModels;

public sealed class LoginViewModel : ObservableObject
{
    private readonly AppSettings _settings;
    private string _server;
    private string _username;
    private string _code = "";
    private string? _error;
    private bool _isBusy;
    private bool _needsCode;
    private string? _challenge;
    private DokuVaultClient? _client;

    public LoginViewModel(AppSettings settings, string? notice = null)
    {
        _settings = settings;
        _server = settings.ServerUrl ?? "";
        _username = settings.Username ?? "";
        _error = notice;
    }

    public string Server
    {
        get => _server;
        set => Set(ref _server, value);
    }

    public string Username
    {
        get => _username;
        set => Set(ref _username, value);
    }

    public string Code
    {
        get => _code;
        set => Set(ref _code, value);
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

    public bool HasError => !string.IsNullOrEmpty(_error);

    public bool IsBusy
    {
        get => _isBusy;
        private set => Set(ref _isBusy, value);
    }

    public bool NeedsCode
    {
        get => _needsCode;
        private set
        {
            if (Set(ref _needsCode, value))
                OnPropertyChanged(nameof(NeedsCredentials));
        }
    }

    public bool NeedsCredentials => !_needsCode;

    /// <summary>The signed-in client and user once the login went through.</summary>
    public (DokuVaultClient Client, User User)? Result { get; private set; }

    public async Task<bool> SignInAsync(string password)
    {
        Error = null;
        if (!DokuVaultClient.TryParseServerUrl(Server, out var url, out var error))
        {
            Error = error;
            return false;
        }
        if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrEmpty(password))
        {
            Error = "Bitte Benutzername und Kennwort eingeben.";
            return false;
        }

        IsBusy = true;
        try
        {
            _client?.Dispose();
            _client = new DokuVaultClient(url!);
            var response = await _client.LoginAsync(Username.Trim(), password, $"Scanner {Environment.MachineName}", CancellationToken.None);
            _settings.ServerUrl = _client.ServerUrl.ToString();
            _settings.Username = Username.Trim();
            SettingsStore.Save(_settings);
            if (response.TwoFactor && response.Challenge is not null)
            {
                _challenge = response.Challenge;
                NeedsCode = true;
                return false;
            }
            return Finish(response);
        }
        catch (DokuVaultApiException e)
        {
            Error = e.Message;
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public async Task<bool> ConfirmCodeAsync()
    {
        Error = null;
        if (_client is null || _challenge is null)
        {
            BackToCredentials();
            return false;
        }
        if (string.IsNullOrWhiteSpace(Code))
        {
            Error = "Bitte den Code aus der Authenticator-App eingeben.";
            return false;
        }

        IsBusy = true;
        try
        {
            return Finish(await _client.LoginTwoFactorAsync(_challenge, Code, CancellationToken.None));
        }
        catch (DokuVaultApiException e)
        {
            Error = e.Message;
            // An expired challenge ends this attempt - a wrong code does not.
            if (e.FieldErrors.ContainsKey("challenge"))
                BackToCredentials(e.Message);
            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }

    public void BackToCredentials(string? message = null)
    {
        _challenge = null;
        Code = "";
        NeedsCode = false;
        Error = message;
    }

    private bool Finish(TokenResponse response)
    {
        if (_client is null || response.Token is null || response.User is null)
        {
            Error = "Der Server hat kein Token geliefert.";
            return false;
        }
        SettingsStore.SaveToken(_client.ServerUrl.ToString(), response.Token);
        Result = (_client, response.User);
        _client = null;
        return true;
    }
}
