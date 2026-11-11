using System.Text.Json;

namespace GuardedDbMcp.Policy;

/// <summary>
/// Who the agent acts for. Attributes feed row-policy filters as bind parameters (e.g. <c>clinic_id = @clinic_id</c>);
/// values are long or string so they bind with the column's type.
/// </summary>
public sealed record Principal(string Name, IReadOnlyDictionary<string, object> Attributes)
{
    public static Principal Anonymous { get; } = new("anonymous", new Dictionary<string, object>());

    public static Principal FromJson(string name, JsonElement attributes)
    {
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        if (attributes.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in attributes.EnumerateObject())
            {
                values[p.Name] = p.Value.ValueKind switch
                {
                    JsonValueKind.Number when p.Value.TryGetInt64(out var l) => l,
                    JsonValueKind.String => p.Value.GetString()!,
                    _ => throw new InvalidDataException($"Principal attribute '{p.Name}' must be an integer or a string."),
                };
            }
        }

        return new Principal(name, values);
    }
}
