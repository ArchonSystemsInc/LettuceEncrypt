// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Options;

namespace LettuceEncrypt
{
    internal class DomainLoader : IDomainLoader
    {
        private static readonly SemaphoreSlim s_sync = new SemaphoreSlim(1, 1);

        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IEnumerable<IDomainSource> _domainSources;
        private readonly ILogger<DomainLoader> _logger;

        private bool _useCache = false;
        private List<IDomainCert> _domainCache = new List<IDomainCert>();

        public DomainLoader(IOptions<LettuceEncryptOptions> options,
            IEnumerable<IDomainSource> domainSources,
            ILogger<DomainLoader> logger)
        {
            _options = options;
            _domainSources = domainSources;
            _logger = logger;
        }

        /// <summary>
        /// Load all domains from <see cref="LettuceEncryptOptions"/> and injected <see cref="IDomainSource"/>.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <param name="refreshCache">Force a cache refresh.</param>
        /// <returns>Distinct set of domains to generate certs for.</returns>
        public async Task<IEnumerable<IDomainCert>> GetDomainCertsAsync(CancellationToken cancellationToken, bool refreshCache = false)
        {
            if (_useCache && !refreshCache)
            {
                return _domainCache;
            }

            await s_sync.WaitAsync(cancellationToken);

            try
            {
                _logger.LogDebug("Loading domain sets");

                var options = _options.Value;

                var domains = new List<IDomainCert>();

                if (options != null && options.DomainNames.Length > 0)
                {
                    domains.Add(new MultipleDomainCert
                    {
                        OrderedDomains = new HashSet<string>(options.DomainNames)
                    });
                }

                foreach (var domainSource in _domainSources)
                {
                    _logger.LogDebug("Loading domains from {domainSource}", domainSource.GetType().Name);

                    domains.AddRange(await domainSource.GetDomains(cancellationToken));
                }

                _domainCache = domains;
                _useCache = true;
            }
            finally
            {
                s_sync.Release();
            }

            return _domainCache;
        }
    }
}
