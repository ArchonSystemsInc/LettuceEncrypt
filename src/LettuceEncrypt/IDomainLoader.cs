// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines the way to provide domains to have certificates generated.
    /// </summary>
    public interface IDomainLoader
    {
        /// <summary>
        /// Gets domains to manage certificates for.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <param name="refreshCache">Force a cache refresh.</param>
        /// <returns>A collection of domains.</returns>
        Task<IEnumerable<IDomainCert>> GetDomainCertsAsync(CancellationToken cancellationToken, bool refreshCache = false);
    }
}
