// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates;

internal class BeginCertificateCreationState : AcmeState
{
    private readonly ILogger<ServerStartupState> _logger;
    private readonly IOptions<LettuceEncryptOptions> _options;
    private readonly AcmeCertificateFactory _acmeCertificateFactory;
    private readonly CertificateSelector _selector;
    private readonly IEnumerable<ICertificateRepository> _certificateRepositories;
    private readonly IDomainLoader _domainLoader;
    private readonly IClock _clock;

    public BeginCertificateCreationState(
        AcmeStateMachineContext context,
        ILogger<ServerStartupState> logger,
        IOptions<LettuceEncryptOptions> options,
        AcmeCertificateFactory acmeCertificateFactory,
        CertificateSelector selector,
        IEnumerable<ICertificateRepository> certificateRepositories,
        IDomainLoader domainLoader,
        IClock clock)
        : base(context)
    {
        _logger = logger;
        _options = options;
        _acmeCertificateFactory = acmeCertificateFactory;
        _selector = selector;
        _certificateRepositories = certificateRepositories;
        _domainLoader = domainLoader;
        _clock = clock;
    }

    public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
    {
        var checkPeriod = _options.Value.RenewalCheckPeriod;
        var daysInAdvance = _options.Value.RenewDaysInAdvance;

        var domainCerts = await _domainLoader.GetDomainCertsAsync(cancellationToken);

        var account = await _acmeCertificateFactory.GetOrCreateAccountAsync(cancellationToken);
        _logger.LogInformation("Using account {accountId}", account.Id);

        var saveTasks = new List<Task>();

        foreach (var domainCert in domainCerts)
        {
            foreach (var domain in domainCert.Domains)
            {
                if (checkPeriod.HasValue && daysInAdvance.HasValue)
                {
                    var cert = await _selector.TryGetAsync(domain);
                    if (cert != null && cert.NotAfter > _clock.Now.DateTime + daysInAdvance.Value)
                    {
                        _logger.LogInformation("Skipping {hostname} since cert already exists and is valid", domain);
                        continue;
                    }
                }

                try
                {
                    _logger.LogInformation("Creating certificate for {hostname}", domainCert.Domains);

                    var newCert = await _acmeCertificateFactory.CreateCertificateAsync(domainCert.Domains, cancellationToken);

                    _logger.LogInformation("Created certificate {subjectName} ({thumbprint})",
                        newCert.Subject,
                        newCert.Thumbprint);

                    // Immediately add to selector incase of overlap between domain sources.
                    await _selector.AddAsync(newCert);

                    saveTasks.Add(SaveCertificateAsync(newCert, cancellationToken));
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostnames}", domainCert.Domains);
                    throw;
                }
            }
        }

        await Task.WhenAll(saveTasks);

        return MoveTo<CheckForRenewalState>();
    }

    private async Task SaveCertificateAsync(X509Certificate2 cert, CancellationToken cancellationToken)
    {
        var saveTasks = new List<Task>
        {
            Task.Delay(TimeSpan.FromMinutes(5), cancellationToken)
        };

        var errors = new List<Exception>();
        foreach (var repo in _certificateRepositories)
        {
            try
            {
                saveTasks.Add(repo.SaveAsync(cert, cancellationToken));
            }
            catch (Exception ex)
            {
                // synchronous saves may fail immediately
                errors.Add(ex);
            }
        }

        await Task.WhenAll(saveTasks);

        if (errors.Count > 0)
        {
            throw new AggregateException("Failed to save cert to repositories", errors);
        }
    }
}
