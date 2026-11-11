# syntax=docker/dockerfile:1

# ---- build -------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Restore in its own layer: it only re-runs when package versions or project files change.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/GuardedDbMcp.Core/GuardedDbMcp.Core.csproj src/GuardedDbMcp.Core/
COPY src/GuardedDbMcp.Postgres/GuardedDbMcp.Postgres.csproj src/GuardedDbMcp.Postgres/
COPY src/GuardedDbMcp.Oracle/GuardedDbMcp.Oracle.csproj src/GuardedDbMcp.Oracle/
COPY src/GuardedDbMcp.Server/GuardedDbMcp.Server.csproj src/GuardedDbMcp.Server/
COPY src/GuardedDbMcp.Demo/GuardedDbMcp.Demo.csproj src/GuardedDbMcp.Demo/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet restore src/GuardedDbMcp.Server/GuardedDbMcp.Server.csproj && \
    dotnet restore src/GuardedDbMcp.Demo/GuardedDbMcp.Demo.csproj

COPY .editorconfig ./
COPY samples/ samples/
COPY src/ src/
RUN --mount=type=cache,id=nuget,target=/root/.nuget/packages \
    dotnet publish src/GuardedDbMcp.Server/GuardedDbMcp.Server.csproj -c Release --no-restore -o /app/server -p:UseAppHost=false && \
    dotnet publish src/GuardedDbMcp.Demo/GuardedDbMcp.Demo.csproj -c Release --no-restore -o /app/demo -p:UseAppHost=false
# Writable directory for the JSONL audit sink, owned by the non-root app user.
RUN mkdir -p /data

# ---- runtime -----------------------------------------------------------------------------------------
# Chiseled Ubuntu: no shell, no package manager, non-root "app" user (UID 1654).
# One image, two entry points: the MCP server (default) and the demo tool (`dotnet /app/demo/guarded-db-demo.dll`).
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
LABEL org.opencontainers.image.title="guarded-db-mcp" \
      org.opencontainers.image.description="Secure MCP server for PostgreSQL and Oracle" \
      org.opencontainers.image.source="https://github.com/hekimcan206/guarded-db-mcp" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build --link /app/server /app/server
COPY --from=build --link /app/demo /app/demo
COPY --from=build --chown=1654:1654 /data /data
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080 \
    GuardedDb__Audit__Path=/data/audit.jsonl
EXPOSE 8080
WORKDIR /app/server
ENTRYPOINT ["dotnet", "/app/server/guarded-db-mcp.dll"]
CMD ["--http"]
