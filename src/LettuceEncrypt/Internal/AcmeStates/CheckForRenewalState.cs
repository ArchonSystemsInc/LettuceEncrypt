// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class CheckForRenewalState : AcmeState
{
    private readonly ILogger<CheckForRenewalState> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly DomainLoader _domains;
    private readonly StartupCertificateLoader _certLoader;
    private readonly CertificateSelector _selector;
    private readonly IClock _clock;

    public CheckForRenewalState(
        AcmeStateMachineContext context,
        ILogger<CheckForRenewalState> logger,
        IOptions<LettuceEncryptOptions> options,
        DomainLoader domains,
        StartupCertificateLoader certLoader,
        CertificateSelector selector,
        IClock clock) : base(context)
    {
        _logger = logger;
        _options = options;
        _domains = domains;
        _certLoader = certLoader;
        _selector = selector;
        _clock = clock;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var checkPeriod = _options.Value.RenewalCheckPeriod;
            var daysInAdvance = _options.Value.RenewDaysInAdvance;
            if (!checkPeriod.HasValue || !daysInAdvance.HasValue)
            {
                _logger.LogInformation("Automatic certificate renewal is not configured. Stopping {service}",
                    nameof(AcmeCertificateLoader));
                return MoveTo<TerminalState>();
            }

            _logger.LogDebug("Loading existing certificates.");
            await _certLoader.LoadAsync(cancellationToken);

            var domainCerts = await _domains.GetDomainCertsAsync(cancellationToken, true);
            foreach (var domainCert in domainCerts)
            {
                foreach (var domain in domainCert.Domains)
                {
                    if (_logger.IsEnabled(LogLevel.Debug))
                    {
                        _logger.LogDebug("Checking certificates' renewals for {hostname}", domain);
                    }

                    var cert = await _selector.TryGetAsync(domain);
                    if (cert == null || cert.NotAfter <= _clock.Now.DateTime + daysInAdvance.Value)
                    {
                        return MoveTo<BeginCertificateCreationState>();
                    }
                }
            }
            await Task.Delay(checkPeriod.Value, cancellationToken);
        }

        return MoveTo<TerminalState>();
    }
}
