// Copyright (c) Nate McMaster & Archon Systems Inc.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Web;

public class Program
{
    public static void Main(string[] args)
    {
        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args) =>
        Host.CreateDefaultBuilder(args)
            .ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();

                // This example shows how to configure Kestrel's client certificate requirements along with
                // enabling Lettuce Encrypt's certificate automation.
                if (Environment.GetEnvironmentVariable("REQUIRE_CLIENT_CERT") == "true")
                {
                    webBuilder.UseKestrel(k =>
                    {
                        k.ConfigureHttpsDefaults(h =>
                        {
                            h.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                        });
                        k.ListenAnyIP(443, o => o.UseLettuceEncrypt(k.ApplicationServices));
                    });
                }

                // This example shows how to configure Kestrel's address/port binding along with
                // enabling Lettuce Encrypt's certificate automation.
                if (Environment.GetEnvironmentVariable("CONFIG_KESTREL_VIA_CODE") == "true")
                {
                    webBuilder.PreferHostingUrls(false);
                    webBuilder.UseKestrel(k =>
                    {
                        k.ListenAnyIP(443, o => o.UseLettuceEncrypt(k.ApplicationServices));
                    });
                }
            });
}
