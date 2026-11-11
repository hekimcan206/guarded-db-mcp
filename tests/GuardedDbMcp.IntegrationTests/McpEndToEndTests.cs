using System.Net;
using System.Security.Cryptography;
using System.Text;
using GuardedDbMcp.Audit;
using GuardedDbMcp.Demo;
using GuardedDbMcp.Pipeline;
using GuardedDbMcp.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace GuardedDbMcp.IntegrationTests;

/// <summary>
/// A real MCP client talking Streamable HTTP to the server's tool class and API-key middleware on Kestrel,
/// backed by PostgreSQL: the protocol path an agent actually uses.
/// </summary>
[Collection("postgres")]
public sealed class McpEndToEndTests(PostgresFixture fixture) : IAsyncLifetime
{
    private const string Key = "integration-test-key";
    private WebApplication? _app;
    private Uri _endpoint = null!;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public async ValueTask InitializeAsync()
    {
        var options = new GuardedDbOptions
        {
            Clients = new()
            {
                ["agent-clinic-1"] = new() { KeySha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Key))), Attributes = new() { ["clinic_id"] = "1" } },
            },
        };
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.SetMinimumLevel(LogLevel.Warning);
        builder.Services.AddSingleton(options);
        builder.Services.AddSingleton<GuardedQueryService>(_ => fixture.CreateService(new InMemoryAuditSink()));
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddSingleton<IPrincipalAccessor, HttpPrincipalAccessor>();
        builder.Services.AddMcpServer().WithHttpTransport(o => o.Stateless = true).WithTools<DatabaseTools>();
        _app = builder.Build();
        _app.UseWhen(c => c.Request.Path.StartsWithSegments("/mcp"), b => b.UseMiddleware<ApiKeyMiddleware>());
        _app.MapMcp("/mcp");
        await _app.StartAsync(Ct);
        _endpoint = new Uri(_app.Urls.First() + "/mcp");
    }

    [Fact]
    public async Task Requests_without_a_valid_key_are_refused()
    {
        using var http = new HttpClient();
        using var anonymous = await http.PostAsync(_endpoint, new StringContent("{}", Encoding.UTF8, "application/json"), Ct);
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint) { Content = new StringContent("{}", Encoding.UTF8, "application/json") };
        request.Headers.Authorization = new("Bearer", "wrong-key");
        using var wrong = await http.SendAsync(request, Ct);

        anonymous.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        wrong.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Agent_sees_three_read_only_tools_and_masked_rows()
    {
        await using var client = await AgentClient.ConnectAsync(_endpoint, Key, Ct);

        (await client.ListToolNamesAsync(Ct)).Should().BeEquivalentTo("list_tables", "describe_table", "query");
        var (text, json) = await client.CallAsync("query", new() { ["sql"] = "SELECT id, tckn, phone FROM patients ORDER BY id FETCH FIRST 3 ROWS ONLY" }, Ct);

        json.GetProperty("ok").GetBoolean().Should().BeTrue(text);
        json.GetProperty("rows")[0][1].GetString().Should().MatchRegex(@"^\*{9}\d{2}$");
        json.GetProperty("notice").GetString().Should().Contain("untrusted");
        Scenarios.Leak(text).Should().BeNull();
    }

    [Fact]
    public async Task Scripted_agent_scenarios_all_pass_except_the_slow_timeout_case()
    {
        await using var client = await AgentClient.ConnectAsync(_endpoint, Key, Ct);

        var outcomes = await Scenarios.RunAsync(client, "postgres", Ct);

        // The policy in this fixture uses a 2 s timeout; every scenario, the timeout included, must pass.
        outcomes.Where(o => !o.Passed).Select(o => $"{o.Scenario.Name}: {o.Detail}").Should().BeEmpty();
    }

    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.DisposeAsync();
        }
    }
}
