// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace LettuceEncrypt
{
    /// <summary>
    ///
    /// </summary>
    public interface IHttpChallengeResponseStore
    {
        /// <summary>
        ///
        /// </summary>
        /// <param name="token"></param>
        /// <param name="response"></param>
        public void AddChallengeResponse(string token, string response);

        /// <summary>
        ///
        /// </summary>
        /// <param name="token"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        public bool TryGetResponse(string token, [MaybeNullWhen(false)] out string? value);
    }
}
