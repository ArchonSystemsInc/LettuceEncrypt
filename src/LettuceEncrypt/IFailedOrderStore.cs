// Copyright (c) Archon Systems.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt;

/// <summary>
///
/// </summary>
internal interface IFailedOrderStore
{
    /// <summary>
    ///
    /// </summary>
    /// <param name="domains"></param>
    /// <param name="expires"></param>
    public void AddOrder(ISet<string> domains, DateTimeOffset expires);

    /// <summary>
    ///
    /// </summary>
    /// <param name="domains"></param>
    /// <returns></returns>
    public DateTimeOffset? GetOrder(ISet<string> domains);
}
