using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace GuardedDbMcp.Pipeline;

/// <summary>OpenTelemetry-compatible traces and metrics via System.Diagnostics; the host decides where they go.</summary>
public static class GuardTelemetry
{
    public const string Name = "GuardedDbMcp";

    public static readonly ActivitySource Source = new(Name, "1.0.0");

    private static readonly Meter Meter = new(Name, "1.0.0");

    public static readonly Counter<long> ToolCalls = Meter.CreateCounter<long>("guarded.tool_calls", description: "Tool calls by tool and outcome");

    public static readonly Counter<long> Rejections = Meter.CreateCounter<long>("guarded.rejections", description: "Guard rejections by code");

    public static readonly Counter<long> RowsReturned = Meter.CreateCounter<long>("guarded.rows_returned");

    public static readonly Counter<long> MaskedValues = Meter.CreateCounter<long>("guarded.masked_values", description: "Cells masked by column policy or value detection");

    public static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("guarded.tool_call.duration", unit: "ms");
}
