using System.Security.Cryptography;
using System.Text;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Server;

/// <summary>Resolves the principal for the current tool call.</summary>
public interface IPrincipalAccessor
{
    Principal Current { get; }
}

/// <summary>stdio: one process serves one agent, so the principal is fixed by configuration.</summary>
public sealed class FixedPrincipalAccessor(Principal principal) : IPrincipalAccessor
{
    public Principal Current { get; } = principal;
}

/// <summary>HTTP: the principal was attached to the request by <see cref="ApiKeyMiddleware"/>.</summary>
public sealed class HttpPrincipalAccessor(IHttpContextAccessor accessor) : IPrincipalAccessor
{
    public Principal Current =>
        accessor.HttpContext?.Items[ApiKeyMiddleware.PrincipalKey] as Principal
        ?? throw new UnauthorizedAccessException("No authenticated principal on this request.");
}

/// <summary>
/// Bearer API keys for the Streamable HTTP endpoint. Keys are compared by SHA-256 in constant time and only
/// hashes are configured. The key identifies the principal whose attributes drive row policy; it is never passed
/// on to the database (the server uses its own read-only credentials — no token passthrough).
/// </summary>
public sealed class ApiKeyMiddleware(RequestDelegate next, GuardedDbOptions options)
{
    public const string PrincipalKey = "guarded-db-mcp.principal";

    private readonly (byte[] Hash, Principal Principal)[] _clients = options.Clients
        .Select(c => (Convert.FromHexString(c.Value.KeySha256), GuardedDbOptions.ToPrincipal(c.Key, c.Value.Attributes)))
        .ToArray();

    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.Ordinal) && Match(header["Bearer ".Length..].Trim()) is { } principal)
        {
            context.Items[PrincipalKey] = principal;
            await next(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Bearer";
    }

    private Principal? Match(string key)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        Principal? found = null;
        foreach (var (expected, principal) in _clients)
        {
            // No early exit: every configured client is compared.
            if (CryptographicOperations.FixedTimeEquals(hash, expected))
            {
                found = principal;
            }
        }

        return found;
    }
}
