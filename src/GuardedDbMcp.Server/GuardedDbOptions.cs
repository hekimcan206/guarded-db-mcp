using System.Globalization;
using GuardedDbMcp.Masking;
using GuardedDbMcp.Policy;

namespace GuardedDbMcp.Server;

public enum AuditSinkKind
{
    Jsonl,
    Postgres,
}

/// <summary>Configuration section "GuardedDb" (environment variables: GuardedDb__Engine, GuardedDb__ConnectionString …).</summary>
public sealed class GuardedDbOptions
{
    public const string Section = "GuardedDb";

    /// <summary>postgres or oracle.</summary>
    public string Engine { get; set; } = "postgres";

    /// <summary>Connection string of the read-only account. Never an owner or DBA account.</summary>
    public string ConnectionString { get; set; } = string.Empty;

    public string PolicyPath { get; set; } = Path.Combine(AppContext.BaseDirectory, "samples", "policy.json");

    /// <summary>Optional override of the policy's rowBudgetPerHour (e.g. for load tests); empty keeps the policy value.</summary>
    public string RowBudgetPerHour { get; set; } = string.Empty;

    /// <summary>Base64, at least 32 bytes. Keys pseudonyms; rotate it and old pseudonyms stop matching.</summary>
    public string PseudonymKey { get; set; } = string.Empty;

    /// <summary>Who a stdio session acts for (one process per agent / user).</summary>
    public PrincipalOptions Principal { get; set; } = new();

    /// <summary>HTTP mode: API clients, each with the SHA-256 of its bearer key and its attributes.</summary>
    public Dictionary<string, ClientOptions> Clients { get; set; } = [];

    public AuditOptions Audit { get; set; } = new();

    public PresidioSettings Presidio { get; set; } = new();

    public sealed class PrincipalOptions
    {
        public string Name { get; set; } = "local-agent";

        public Dictionary<string, string> Attributes { get; set; } = [];
    }

    public sealed class ClientOptions
    {
        public string KeySha256 { get; set; } = string.Empty;

        public Dictionary<string, string> Attributes { get; set; } = [];
    }

    public sealed class AuditOptions
    {
        public AuditSinkKind Sink { get; set; } = AuditSinkKind.Jsonl;

        public string Path { get; set; } = "guarded-db-mcp-audit.jsonl";

        /// <summary>For Sink=Postgres: the audit-writer login (EXECUTE on audit.append_tool_call only).</summary>
        public string ConnectionString { get; set; } = string.Empty;
    }

    public sealed class PresidioSettings
    {
        /// <summary>Base URL of the Presidio analyzer, e.g. http://presidio:3000/. Empty: built-in recognisers only.</summary>
        public string Url { get; set; } = string.Empty;

        public AnalyzerFailureMode FailureMode { get; set; } = AnalyzerFailureMode.Closed;

        public double ScoreThreshold { get; set; } = 0.5;
    }

    public static GuardedDbOptions From(IConfiguration configuration)
    {
        var options = new GuardedDbOptions();
        configuration.GetSection(Section).Bind(options);
        return options;
    }

    public byte[] PseudonymKeyBytes()
    {
        if (string.IsNullOrWhiteSpace(PseudonymKey))
        {
            throw new InvalidOperationException("GuardedDb:PseudonymKey is required (base64, at least 32 bytes).");
        }

        var bytes = Convert.FromBase64String(PseudonymKey);
        return bytes.Length >= 32 ? bytes : throw new InvalidOperationException("GuardedDb:PseudonymKey must decode to at least 32 bytes.");
    }

    /// <summary>Configuration values are strings; integers become long so they bind with integer columns.</summary>
    public static Principal ToPrincipal(string name, IReadOnlyDictionary<string, string> attributes) => new(
        name,
        attributes.ToDictionary(
            kv => kv.Key,
            kv => long.TryParse(kv.Value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l) ? (object)l : kv.Value,
            StringComparer.OrdinalIgnoreCase));
}
