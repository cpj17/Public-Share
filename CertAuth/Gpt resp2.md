How to implement mTLS using .net core
------------

Below is a clear, production-ready guide to implement Mutual TLS (mTLS) in .NET Core / ASP.NET Core, covering API + client, cert creation, and common pitfalls.

🔐 What is mTLS (Mutual TLS)?

In mTLS, both client and server authenticate each other using certificates.

Component	Authenticates
Server	Client certificate
Client	Server certificate

Used heavily in:

Banking & FinTech APIs

Microservices (Zero Trust)

Internal secure APIs

🏗 Architecture Flow
Client ----(Client Cert)---> Server
Client <---(Server Cert)---- Server

✅ Step-by-Step Implementation
1️⃣ Generate Certificates (Dev / Test)
Create a Root CA
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.pem

Create Server Certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out server.crt -days 365 -sha256

Create Client Certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA rootCA.pem -CAkey rootCA.key \
  -CAcreateserial -out client.crt -days 365 -sha256


👉 Convert to .pfx (required for .NET):

openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt
openssl pkcs12 -export -out server.pfx -inkey server.key -in server.crt

2️⃣ Configure ASP.NET Core Server (mTLS)
Program.cs (ASP.NET Core 6+)
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        https.CheckCertificateRevocation = false;

        https.ClientCertificateValidation = (cert, chain, errors) =>
        {
            if (errors != SslPolicyErrors.None)
                return false;

            return cert.Issuer.Contains("YourRootCA");
        };
    });
});

Enable Certificate Authentication
builder.Services.AddAuthentication("Certificate")
    .AddCertificate(options =>
    {
        options.AllowedCertificateTypes = CertificateTypes.All;
        options.ValidateCertificateUse = true;
        options.ValidateValidityPeriod = true;
    });

app.UseAuthentication();
app.UseAuthorization();

Secure Controller / Endpoint
[Authorize(AuthenticationSchemes = "Certificate")]
[ApiController]
[Route("api/secure")]
public class SecureController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var clientCert = HttpContext.Connection.ClientCertificate;
        return Ok($"Hello {clientCert.Subject}");
    }
}

3️⃣ Configure .NET Client (HttpClient with Client Cert)
var handler = new HttpClientHandler();

handler.ClientCertificates.Add(
    new X509Certificate2("client.pfx", "pfx-password")
);

handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

var client = new HttpClient(handler);

var response = await client.GetAsync("https://localhost:5001/api/secure");
var content = await response.Content.ReadAsStringAsync();

4️⃣ Validate Client Certificate Claims (Advanced)
options.Events = new CertificateAuthenticationEvents
{
    OnCertificateValidated = context =>
    {
        var cert = context.ClientCertificate;

        if (!cert.Subject.Contains("MyTrustedClient"))
        {
            context.Fail("Unauthorized client");
        }

        context.Success();
        return Task.CompletedTask;
    }
};

5️⃣ Production Best Practices 🚀

✅ Use proper CA (not self-signed)
✅ Enable CRL / OCSP
✅ Validate Thumbprint or SAN
✅ Rotate certificates regularly
✅ Use API Gateway / Nginx / Envoy for TLS termination

6️⃣ mTLS Behind NGINX (Recommended)
ssl_client_certificate /etc/nginx/ca.pem;
ssl_verify_client on;


ASP.NET Core will receive client cert via header.

⚠ Common Issues & Fixes
Issue	Fix
403 Forbidden	Missing [Authorize]
Client cert not detected	RequireCertificate not enabled
Works locally, fails prod	Load cert to OS store
Kestrel ignores cert	HTTPS not bound correctly
🧪 How to Test
curl --cert client.crt --key client.key https://localhost:5001/api/secure

🔚 Summary

✔ mTLS secures both client & server
✔ ASP.NET Core supports it natively
✔ Ideal for microservices, fintech, internal APIs

If you want, I can also provide:

🔹 mTLS with NGINX + .NET

🔹 mTLS in Kubernetes

🔹 Certificate rotation strategy

🔹 Diagram / PDF

Just tell me 👍
