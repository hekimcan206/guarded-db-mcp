```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.9711/25H2/2025Update/HudsonValley2)
13th Gen Intel Core i7-13620H 2.40GHz, 1 CPU, 16 logical and 10 physical cores
.NET SDK 10.0.401
  [Host]     : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3
  DefaultJob : .NET 10.0.12 (10.0.12, 10.0.1226.42308), X64 RyuJIT x86-64-v3


```
| Method                   | Mean     | Error   | StdDev   | Gen0    | Gen1   | Allocated |
|------------------------- |---------:|--------:|---------:|--------:|-------:|----------:|
| ClassifiedColumns200Rows | 382.1 μs | 7.57 μs | 19.42 μs | 27.3438 | 4.3945 | 335.98 KB |
| FreeText200Rows          | 453.8 μs | 5.88 μs |  4.91 μs | 43.9453 | 6.3477 | 539.96 KB |
