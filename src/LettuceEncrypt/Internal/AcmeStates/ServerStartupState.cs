// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class ServerStartupState : AcmeState
    {
        private readonly IDomainLoader _domainLoader;
        private readonly StartupCertificateLoader _certLoader;
        private readonly CertificateSelector _selector;
        private readonly ILogger<ServerStartupState> _logger;

        public ServerStartupState(
            AcmeStateMachineContext context,
            IDomainLoader domainLoader,
            StartupCertificateLoader certLoader,
            CertificateSelector selector,
            ILogger<ServerStartupState> logger) :
            base(context)
        {
            _domainLoader = domainLoader;
            _certLoader = certLoader;
            _selector = selector;
            _logger = logger;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            _logger.LogDebug("Loading existing certificates.");
            await _certLoader.LoadAsync(cancellationToken);

            var domains = await _domainLoader.GetDomainCertsAsync(cancellationToken);
            var hasCertForAllDomains = domains.All(_selector.HasCertForDomain);
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for {domainNames} already found.", domains);
                return MoveTo<CheckForRenewalState>();
            }

            return MoveTo<BeginCertificateCreationState>();
        }
    }
}
