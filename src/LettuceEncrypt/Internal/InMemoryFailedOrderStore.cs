// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;

namespace LettuceEncrypt.Internal;

internal class InMemoryFailedOrderStore : IFailedOrderStore
{
    // Hash -> Order DateTimeOffset
    private readonly ConcurrentDictionary<string, DateTimeOffset> _values = new();

    public void AddOrder(ISet<string> domains, DateTimeOffset expires)
    {
        _values.AddOrUpdate(GetHash(domains), expires, (_, _) => expires);
    }

    public DateTimeOffset? GetOrder(ISet<string> domains)
    {
        return _values.TryGetValue(GetHash(domains), out var expires) ? expires : null;
    }

    private static string GetHash(ISet<string> domains)
    {
        return string.Join("", domains.Select(x => x.GetHashCode()));
    }
}
