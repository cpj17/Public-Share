using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Authentication;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using static System.Net.WebRequestMethods;

var builder = WebApplication.CreateBuilder(args);

#region CertAuth
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(o =>
    {
        o.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        o.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    });
});

builder.Services
    .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.RevocationMode = X509RevocationMode.NoCheck;

        options.Events = new CertificateAuthenticationEvents
        {
            OnCertificateValidated = context =>
            {
                var cert = context.ClientCertificate;

                // Expiry validation (correct)
                if (DateTime.UtcNow < cert.NotBefore ||
                    DateTime.UtcNow > cert.NotAfter)
                {
                    context.Fail("Certificate expired or not valid yet");
                    return Task.CompletedTask;
                }

                // STRONGEST CHECK (thumbprint pinning)
                if (!string.Equals(
                        cert.Thumbprint,
                        "3B01C7D75AD75323F973BDFBE9F6E1874E8D9704",
                        StringComparison.OrdinalIgnoreCase))
                {
                    context.Fail("Invalid certificate");
                    return Task.CompletedTask;
                }

                // Build identity
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, cert.Subject),
                    new Claim("thumbprint", cert.Thumbprint)
                };

                context.Principal = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, context.Scheme.Name));

                context.Success();
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
#endregion

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
