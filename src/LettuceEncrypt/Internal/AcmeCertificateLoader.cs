// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.AcmeStates;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace LettuceEncrypt.Internal;

/// <summary>
/// This starts the ACME state machine, which handles certificate generation and renewal
/// </summary>
internal class AcmeCertificateLoader : BackgroundService, IAcmeCertificateLoader
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly ILogger _logger;

    private readonly IServer _server;
    private readonly IConfiguration _config;

    public AcmeCertificateLoader(
        IServiceScopeFactory serviceScopeFactory,
        ILogger<AcmeCertificateLoader> logger,
        IServer server,
        IConfiguration config)
    {
        _serviceScopeFactory = serviceScopeFactory;
        _logger = logger;
        _server = server;
        _config = config;
    }

    public bool IsRunning { get; private set; } = false;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_server.GetType().Name.StartsWith(nameof(KestrelServer)))
        {
            var serverType = _server.GetType().FullName;
            _logger.LogWarning(
                "LettuceEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.",
                serverType);
            return;
        }

        if (_config.GetValue<bool>("UseIISIntegration"))
        {
            _logger.LogWarning(
                "LettuceEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding." +
                "Skipping certificate provisioning.");
            return;
        }

        using var acmeStateMachineScope = _serviceScopeFactory.CreateScope();

        try
        {
            IsRunning = true;

            IAcmeState state = acmeStateMachineScope.ServiceProvider.GetRequiredService<ServerStartupState>();

            while (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogTrace("ACME state transition: moving to {stateName}", state.GetType().Name);
                state = await state.MoveNextAsync(stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("State machine cancellation requested. Exiting...");
        }
        catch (AggregateException ex) when (ex.InnerException != null)
        {
            _logger.LogError(0, ex.InnerException, "ACME state machine encountered unhandled error");
        }
        catch (Exception ex)
        {
            _logger.LogError(0, ex, "ACME state machine encountered unhandled error");
        }
        finally
        {
            IsRunning = false;
        }
    }
}
