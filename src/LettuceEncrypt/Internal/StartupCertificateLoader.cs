﻿// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal
{
    internal class StartupCertificateLoader
    {
        private readonly IEnumerable<ICertificateSource> _certSources;
        private readonly CertificateSelector _selector;
        private readonly ILogger<StartupCertificateLoader> _logger;

        public StartupCertificateLoader(
            IEnumerable<ICertificateSource> certSources,
            CertificateSelector selector,
            ILogger<StartupCertificateLoader> logger)
        {
            _certSources = certSources;
            _selector = selector;
            _logger = logger;
        }

        public async Task LoadAsync(CancellationToken cancellationToken)
        {
            var allCerts = new List<X509Certificate2>();
            foreach (var certSource in _certSources)
            {
                _logger.LogDebug("Loading certs from source {certSource}", certSource.GetType().Name);

                var certs = await certSource.GetCertificatesAsync(cancellationToken);
                allCerts.AddRange(certs);
            }

            // Add newer certificates first. This avoid potentially unnecessary cert validations on older certificates
            foreach (var cert in allCerts.OrderByDescending(c => c.NotAfter))
            {
                _logger.LogDebug("Loading certificate: {certificate}", cert.FriendlyName);
                await _selector.AddAsync(cert);
            }
        }
    }
}
