// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt
{
    /// <summary>
    /// Manages certifactes during runtime
    /// </summary>
    public interface IRuntimeCertificateStore
    {
        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        Task<X509Certificate2> AddCertWithDomainNameAsync(string domainName, X509Certificate2 certificate);
        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <param name="certificate"></param>
        /// <returns></returns>
        Task<X509Certificate2> AddChallengeCertWithDomainNameAsync(string domainName, X509Certificate2 certificate);

        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        Task<X509Certificate2?> GetCertAsync(string domainName);
        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        Task<X509Certificate2?> GetChallengeCertAsync(string domainName);

        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        Task<bool> AnyChallengeCertAsync();
        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        Task<bool> ContainsCertForDomainAsync(string domainName);
        /// <summary>
        ///
        /// </summary>
        /// <returns></returns>
        Task<IEnumerable<string>> GetAllCertDomainsAsync();

        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        Task<bool> RemoveCertAsync(string domainName);
        /// <summary>
        ///
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        Task<bool> RemoveChallengeCertAsync(string domainName);
    }
}
