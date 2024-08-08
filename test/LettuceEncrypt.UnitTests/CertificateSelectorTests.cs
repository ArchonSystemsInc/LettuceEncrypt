// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

using static TestUtils;

public class CertificateSelectorTests
{
    [Fact]
    public async Task ItUsesCertCommonNameAsync()
    {
        const string CommonName = "selector.test.natemcmaster.com";

        var testCert = CreateTestCert(CommonName);
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance,
            new InMemoryRuntimeCertificateStore());

        await selector.AddAsync(testCert);

        var domain = Assert.Single(selector.SupportedDomains);
        Assert.Equal(CommonName, domain);
    }

    [Fact]
    public async Task ItUsesSubjectAlternativeNameAsync()
    {
        var domainNames = new[]
        {
                "san1.test.natemcmaster.com",
                "san2.test.natemcmaster.com",
                "san3.test.natemcmaster.com",
            };
        var testCert = CreateTestCert(domainNames);
        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance,
            new InMemoryRuntimeCertificateStore());

        await selector.AddAsync(testCert);


        Assert.Equal(
            new HashSet<string>(domainNames),
            new HashSet<string>(selector.SupportedDomains));
    }

    [Fact]
    public async Task ItSelectsCertificateWithLongestTTL()
    {
        const string CommonName = "test.natemcmaster.com";
        var fiveDays = CreateTestCert(CommonName, DateTimeOffset.Now.AddDays(5));
        var tenDays = CreateTestCert(CommonName, DateTimeOffset.Now.AddDays(10));

        var selector = new CertificateSelector(
            Options.Create(new LettuceEncryptOptions()),
            NullLogger<CertificateSelector>.Instance,
            new InMemoryRuntimeCertificateStore());

        await selector.AddAsync(fiveDays);
        await selector.AddAsync(tenDays);

        Assert.Same(tenDays, await selector.SelectAsync(Mock.Of<ConnectionContext>(), CommonName));

        await selector.ResetAsync(CommonName);

        Assert.Null(await selector.SelectAsync(Mock.Of<ConnectionContext>(), CommonName));

        await selector.AddAsync(tenDays);
        await selector.AddAsync(fiveDays);

        Assert.Same(tenDays, await selector.SelectAsync(Mock.Of<ConnectionContext>(), CommonName));
    }
}
