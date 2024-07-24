// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines a source for domains that will be considered for creation/renewal
    /// </summary>
    public interface IDomainSource
    {
        /// <summary>
        /// Gets a collection of domains that will be consdered for creation/renewal.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task<IEnumerable<IDomainCert>> GetDomains(CancellationToken cancellationToken);
    }

    /// <summary>
    /// Defines a certificate request with one or multiple domains
    /// </summary>
    public interface IDomainCert
    {   /// <summary>
        /// Domains the cert should be requested for
        /// </summary>
        public ISet<string> Domains { get; }
    }

    /// <summary>
    /// Default single domain cert implemenation
    /// </summary>
    public class SingleDomainCert : IDomainCert
    {
        /// <summary>
        /// Domain to request standalone cert for
        /// </summary>
        public string Domain { get; set; } = default!;

        /// <inheritdoc/>
        public ISet<string> Domains => new HashSet<string> { Domain };
    }

    /// <summary>
    /// Default multiple domain cert implementation
    /// </summary>
    public class MultipleDomainCert : IDomainCert
    {
        /// <summary>
        /// Ordered domains to request multiple domain cert for.
        /// The first domain in this set will be used as the common name.
        /// </summary>
        public HashSet<string> OrderedDomains { get; set; } = default!;

        /// <inheritdoc/>
        public ISet<string> Domains => OrderedDomains;
    }
}
