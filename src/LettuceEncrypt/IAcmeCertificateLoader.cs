// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt
{
    /// <summary>
    /// Service running state machine for cert loading and renewal
    /// </summary>
    public interface IAcmeCertificateLoader : IHostedService
    {
        /// <summary>
        /// Determine if the ACME service is running
        /// </summary>
        public bool IsRunning { get; }
    }
}
