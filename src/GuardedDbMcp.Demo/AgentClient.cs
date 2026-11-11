using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace GuardedDbMcp.Demo;

/// <summary>A thin MCP client over Streamable HTTP that plays the part of an agent.</summary>
public sealed class AgentClient : IAsyncDisposable
{
    private readonly McpClient _client;

    private AgentClient(McpClient client) => _client = client;

    public static async Task<AgentClient> ConnectAsync(Uri endpoint, string bearerKey, CancellationToken cancellationToken = default)
    {
        var transport = new HttpClientTransport(new HttpClientTransportOptions
        {
            Endpoint = endpoint,
            TransportMode = HttpTransportMode.StreamableHttp,
            AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + bearerKey },
            Name = "guarded-db-demo",
        });
        return new AgentClient(await McpClient.CreateAsync(transport, cancellationToken: cancellationToken));
    }

    public async Task<IReadOnlyList<string>> ListToolNamesAsync(CancellationToken cancellationToken = default) =>
        (await _client.ListToolsAsync(cancellationToken: cancellationToken)).Select(t => t.Name).ToList();

    /// <summary>Calls a tool and returns the raw JSON text the agent would see, parsed.</summary>
    public async Task<(string Text, JsonElement Json)> CallAsync(string tool, Dictionary<string, object?> arguments, CancellationToken cancellationToken = default)
    {
        var result = await _client.CallToolAsync(tool, arguments, cancellationToken: cancellationToken);
        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(t => t.Text));
        using var doc = JsonDocument.Parse(text);
        return (text, doc.RootElement.Clone());
    }

    public ValueTask DisposeAsync() => _client.DisposeAsync();
}
