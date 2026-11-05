using System.Net;
using System.Security.Cryptography;
using System.Text;
using DokuVault.Scanner.Core.Update;

namespace DokuVault.Scanner.Tests;

public sealed class UpdateTests : IDisposable
{
    private static readonly Uri Latest = new("https://updates.test/latest");
    private static readonly Uri Downloads = new("https://updates.test/download/");
    private static readonly byte[] Exe = Encoding.ASCII.GetBytes("MZ the new version");

    private readonly string _folder = Directory.CreateTempSubdirectory("dokuvault-update-").FullName;

    private string Target => Path.Combine(_folder, UpdateClient.ExeName);

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    private sealed class Handler(Func<Uri, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);
            return Task.FromResult(answer(request.RequestUri!));
        }
    }

    private static HttpResponseMessage Ok(byte[] body) => new(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
    private static HttpResponseMessage Ok(string body) => Ok(Encoding.UTF8.GetBytes(body));
    private static string Checksum(byte[] body) => Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();

    private static UpdateClient Client(Handler handler, long maxBytes = 1024) => new(Latest, Downloads, handler, maxBytes);

    private static Task<AvailableUpdate?> CheckAsync(string answer, string current = "1.2.0.0") =>
        Client(new Handler(_ => Ok(answer))).CheckAsync(Version.Parse(current), CancellationToken.None);

    private static Handler Release(byte[] exe, string checksum) => new(uri => uri.AbsolutePath switch
    {
        "/download/v1.3.0/DokuVaultScanner.exe" => Ok(exe),
        "/download/v1.3.0/DokuVaultScanner.exe.sha256" => Ok(checksum),
        _ => new HttpResponseMessage(HttpStatusCode.NotFound),
    });

    private static readonly AvailableUpdate Update = new(new Version(1, 3, 0), "v1.3.0");

    [Theory]
    [InlineData("v1.3.0", "1.2.0.0")]
    [InlineData("v1.2.1", "1.2.0.0")]
    [InlineData("v2.0.0", "1.9.9.0")]
    [InlineData("v1.10.0", "1.9.0.0")]
    public async Task A_newer_release_is_an_update(string tag, string current)
    {
        var update = await CheckAsync($$"""{"tag_name":"{{tag}}"}""", current);
        Assert.Equal(tag, update?.Tag);
    }

    [Theory]
    [InlineData("v1.2.0")]
    [InlineData("v1.1.9")]
    public async Task The_same_or_an_older_release_is_none(string tag) =>
        Assert.Null(await CheckAsync($$"""{"tag_name":"{{tag}}"}"""));

    [Theory]
    [InlineData("""{"tag_name":"v9.0.0-rc1"}""")]
    [InlineData("""{"tag_name":"9.0.0"}""")]
    [InlineData("""{"tag_name":"v9.0"}""")]
    [InlineData("""{"tag_name":"v9.0.0/../../evil"}""")]
    [InlineData("""{"tag_name":"v9.0.0\n"}""")]
    [InlineData("""{"tag_name":"v٩.0.0"}""")]
    [InlineData("""{"tag_name":9}""")]
    [InlineData("""{"message":"Not Found"}""")]
    [InlineData("""[]""")]
    [InlineData("<html>")]
    [InlineData("")]
    public async Task An_unusable_answer_is_no_update(string answer) =>
        Assert.Null(await CheckAsync(answer));

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task A_refusal_is_no_update(HttpStatusCode status)
    {
        var handler = new Handler(_ => new HttpResponseMessage(status) { Content = new StringContent("""{"tag_name":"v9.0.0"}""") });
        Assert.Null(await Client(handler).CheckAsync(new Version(1, 2, 0), CancellationToken.None));
    }

    [Fact]
    public async Task Being_offline_is_no_update()
    {
        var handler = new Handler(_ => throw new HttpRequestException("offline"));
        Assert.Null(await Client(handler).CheckAsync(new Version(1, 2, 0), CancellationToken.None));
    }

    [Fact]
    public async Task A_timeout_is_no_update()
    {
        var handler = new Handler(_ => throw new TaskCanceledException());
        Assert.Null(await Client(handler).CheckAsync(new Version(1, 2, 0), CancellationToken.None));
    }

    [Theory]
    [InlineData("  DokuVaultScanner.exe\n")]
    [InlineData("")]
    public async Task Check_and_download_use_the_configured_addresses_only(string suffix)
    {
        var checksum = Checksum(Exe);
        var handler = Release(Exe, suffix.Length == 0 ? checksum : checksum + suffix);
        await Client(handler).DownloadAsync(Update, Target, null, CancellationToken.None);

        Assert.Equal(Exe, await File.ReadAllBytesAsync(Target));
        Assert.All(handler.Requests, uri => Assert.StartsWith(Downloads.ToString(), uri.ToString()));
    }

    [Fact]
    public async Task Checksum_case_does_not_matter()
    {
        await Client(Release(Exe, Checksum(Exe).ToUpperInvariant())).DownloadAsync(Update, Target, null, CancellationToken.None);
        Assert.True(File.Exists(Target));
    }

    [Fact]
    public async Task A_wrong_checksum_leaves_no_file()
    {
        var handler = Release(Exe, Checksum(Encoding.ASCII.GetBytes("something else")));
        await Assert.ThrowsAsync<UpdateException>(() => Client(handler).DownloadAsync(Update, Target, null, CancellationToken.None));
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public async Task A_file_that_is_no_program_leaves_no_file()
    {
        var text = Encoding.ASCII.GetBytes("no program");
        await Assert.ThrowsAsync<UpdateException>(() => Client(Release(text, Checksum(text))).DownloadAsync(Update, Target, null, CancellationToken.None));
        Assert.False(File.Exists(Target));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not a checksum")]
    [InlineData("<html>404</html>")]
    public async Task An_unreadable_checksum_file_leaves_no_file(string checksum)
    {
        await Assert.ThrowsAsync<UpdateException>(() => Client(Release(Exe, checksum)).DownloadAsync(Update, Target, null, CancellationToken.None));
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public async Task A_missing_exe_leaves_no_file()
    {
        var handler = new Handler(uri => uri.AbsolutePath.EndsWith(".sha256") ? Ok(Checksum(Exe)) : new HttpResponseMessage(HttpStatusCode.NotFound));
        var error = await Assert.ThrowsAsync<UpdateException>(() => Client(handler).DownloadAsync(Update, Target, null, CancellationToken.None));
        Assert.Contains("404", error.Message);
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public async Task An_oversized_exe_leaves_no_file()
    {
        var huge = new byte[2048];
        await Assert.ThrowsAsync<UpdateException>(() => Client(Release(huge, Checksum(huge))).DownloadAsync(Update, Target, null, CancellationToken.None));
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public async Task A_cancelled_download_leaves_no_file()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Client(Release(Exe, Checksum(Exe))).DownloadAsync(Update, Target, null, cancelled.Token));
        Assert.False(File.Exists(Target));
    }

    [Fact]
    public async Task Progress_reaches_the_end()
    {
        var seen = new List<double>();
        await Client(Release(Exe, Checksum(Exe))).DownloadAsync(Update, Target, new Immediate(seen.Add), CancellationToken.None);
        Assert.Equal(1d, seen[^1]);
    }

    private sealed class Immediate(Action<double> report) : IProgress<double>
    {
        public void Report(double value) => report(value);
    }

    private string UpdateExe => ExeSwap.UpdatePath(Target);

    [Fact]
    public void The_update_file_is_named_after_the_exe_and_points_back()
    {
        Assert.Equal(Path.Combine(_folder, "DokuVaultScanner.update.exe"), UpdateExe);
        Assert.Equal(Target, ExeSwap.TargetOf(UpdateExe));
        Assert.Null(ExeSwap.TargetOf(Target));
    }

    [Fact]
    public void Install_replaces_the_exe_and_keeps_the_running_update_file()
    {
        File.WriteAllText(Target, "old");
        File.WriteAllText(UpdateExe, "new");

        ExeSwap.Install(UpdateExe);

        Assert.Equal("new", File.ReadAllText(Target));
        Assert.Equal("new", File.ReadAllText(UpdateExe));
        Assert.Equal(2, Directory.GetFiles(_folder).Length);
    }

    [Fact]
    public void Install_works_without_an_old_exe()
    {
        File.WriteAllText(UpdateExe, "new");
        ExeSwap.Install(UpdateExe);
        Assert.Equal("new", File.ReadAllText(Target));
    }

    [Fact]
    public void An_exe_in_use_stays_whole_and_nothing_is_left()
    {
        File.WriteAllText(Target, "old");
        File.WriteAllText(UpdateExe, "new");

        using (File.Open(Target, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.ThrowsAny<Exception>(() => ExeSwap.Install(UpdateExe, attempts: 2, pauseMilliseconds: 1));

        Assert.Equal("old", File.ReadAllText(Target));
        Assert.Equal(2, Directory.GetFiles(_folder).Length);
    }

    [Fact]
    public void Install_refuses_any_other_file()
    {
        Assert.Throws<ArgumentException>(() => ExeSwap.Install(Target));
    }

    [Fact]
    public async Task Leftovers_go_and_the_exe_stays()
    {
        File.WriteAllText(Target, "new");
        File.WriteAllText(UpdateExe, "update");
        File.WriteAllText(Target + ".new", "partial copy");

        await ExeSwap.RemoveLeftoversAsync(Target, attempts: 1);

        Assert.Equal([Target], Directory.GetFiles(_folder));
    }

    [Fact]
    public async Task A_locked_leftover_does_not_throw()
    {
        using (File.Open(UpdateExe, FileMode.Create, FileAccess.Write, FileShare.None))
            await ExeSwap.RemoveLeftoversAsync(Target, attempts: 2, pauseMilliseconds: 1);
        Assert.True(File.Exists(UpdateExe));
    }

    [Fact]
    public async Task A_leftover_is_retried_until_it_is_free()
    {
        var holder = File.Open(UpdateExe, FileMode.Create, FileAccess.Write, FileShare.None);
        var cleanup = ExeSwap.RemoveLeftoversAsync(Target, attempts: 400, pauseMilliseconds: 5);
        await Task.Delay(30);
        holder.Dispose();
        await cleanup;
        Assert.False(File.Exists(UpdateExe));
    }
}
