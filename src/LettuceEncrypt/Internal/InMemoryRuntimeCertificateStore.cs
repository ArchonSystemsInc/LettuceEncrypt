// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt.Internal
{
    internal class InMemoryRuntimeCertificateStore : IRuntimeCertificateStore
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certs =
            new(StringComparer.OrdinalIgnoreCase);

        private readonly ConcurrentDictionary<string, X509Certificate2> _challengeCerts =
            new(StringComparer.OrdinalIgnoreCase);

        public Task<X509Certificate2> AddCertWithDomainNameAsync(string domainName, X509Certificate2 certificate)
        {
            return Task.FromResult(_certs.AddOrUpdate(
                domainName,
                certificate,
                (_, currentCert) =>
                {
                    if (currentCert == null || certificate.NotAfter >= currentCert.NotAfter)
                    {
                        return certificate;
                    }

                    return currentCert;
                }));
        }

        public Task<X509Certificate2> AddChallengeCertWithDomainNameAsync(string domainName, X509Certificate2 certificate)
        {
            return Task.FromResult(_challengeCerts.AddOrUpdate(
                domainName,
                certificate,
                (_, currentCert) =>
                {
                    if (currentCert == null || certificate.NotAfter >= currentCert.NotAfter)
                    {
                        return certificate;
                    }

                    return currentCert;
                }));
        }

        public Task<X509Certificate2?> GetCertAsync(string domainName)
        {
            if (_certs.TryGetValue(domainName, out var certificate))
            {
                return Task.FromResult((X509Certificate2?)certificate);
            }
            else
            {
                return Task.FromResult((X509Certificate2?)null);
            }
        }

        public Task<X509Certificate2?> GetChallengeCertAsync(string domainName)
        {
            if (_challengeCerts.TryGetValue(domainName, out var certificate))
            {
                return Task.FromResult((X509Certificate2?)certificate);
            }
            else
            {
                return Task.FromResult((X509Certificate2?)null);
            }
            throw new NotImplementedException();
        }

        public Task<bool> RemoveCertAsync(string domainName)
        {
            return Task.FromResult(_certs.TryRemove(domainName, out _));
        }

        public Task<bool> RemoveChallengeCertAsync(string domainName)
        {
            return Task.FromResult(_challengeCerts.TryRemove(domainName, out _));
        }

        public Task<bool> AnyChallengeCertAsync()
        {
            return Task.FromResult(_challengeCerts.Count > 0);
        }

        public Task<bool> ContainsCertForDomainAsync(string domainName)
        {
            return Task.FromResult(_certs.ContainsKey(domainName));
        }

        public Task<IEnumerable<string>> GetAllCertDomainsAsync()
        {
            return Task.FromResult(_certs.Keys as IEnumerable<string>);
        }
    }
}
