using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HttpsCertExperiments
{
    class Program
    {
        public static string Subject => "CN=localhost";
        public static int AspNetHttpsCertificateVersion => 2;

        private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
        private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";
        internal const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";

        static void Main(string[] args)
        {
            ClearCertificates();
            var ca = CreateCaCertificate();
            var https = CreateHttpsCertificate(ca);
            SaveCertificate(ca);
            SaveCertificate(https);
            ExportCertificate("ca", ca);
            ExportCertificate("localhost", https);
        }

        private static void ExportCertificate(string name, X509Certificate2 cert)
        {
            var bytes = cert.Export(X509ContentType.Pkcs12, "1234");
            File.WriteAllBytes($"{name}.pfx", bytes);
        }

        private static void SaveCertificate(X509Certificate2 certificate)
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            store.Add(certificate);

            store.Close();
        }

        private static X509Certificate2 CreateHttpsCertificate(X509Certificate2 ca)
        {
            return CreateAspNetCoreHttpsDevelopmentCertificate(ca, DateTime.Now, DateTime.Now.AddYears(1));
        }

        private static X509Certificate2 CreateCaCertificate()
        {
            var notBefore = DateTime.Now;
            var notAfter = DateTime.Now.AddYears(1).AddSeconds(5);

            var subject = new X500DistinguishedName("CN=ASP.NET Core CA");
            var extensions = new List<X509Extension>();

            var keyUsages = X509KeyUsageFlags.CrlSign |
                            X509KeyUsageFlags.DigitalSignature |
                            X509KeyUsageFlags.KeyCertSign |
                            X509KeyUsageFlags.NonRepudiation;

            var keyUsage = new X509KeyUsageExtension(keyUsages, critical: true);
            
            var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
                new OidCollection() {
                    new Oid(
                        ServerAuthenticationEnhancedKeyUsageOid,
                        ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
                },
                critical: true);


            var basicConstraints = new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: true,
                pathLengthConstraint: 1,
                critical: true);

            var bytePayload = new byte[1];
            bytePayload[0] = (byte)AspNetHttpsCertificateVersion;

            var aspNetHttpsExtension = new X509Extension(
                new AsnEncodedData(
                    new Oid(AspNetHttpsOid, "ASP.NET Core HTTPS development certificate"),
                    bytePayload),
                critical: false);

            extensions.Add(basicConstraints);
            extensions.Add(keyUsage);
            extensions.Add(enhancedKeyUsage);
            extensions.Add(aspNetHttpsExtension);

            return CreateSelfSignedCertificate(subject, extensions, notBefore, notAfter);
        }

        private static void ClearCertificates()
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            var certificates = store.Certificates.Cast<X509Certificate2>()
                .Where(c => c.Extensions.Cast<X509Extension>()
                    .Any(e => e.Oid.Value == "1.3.6.1.4.1.311.84.1.1"))
                .ToArray();

            store.Certificates.RemoveRange(certificates);
            
            store.Close();
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }

        internal static X509Certificate2 CreateAspNetCoreHttpsDevelopmentCertificate(X509Certificate2 ca, DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            var subject = new X500DistinguishedName(Subject);
            var extensions = new List<X509Extension>();
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");

            var keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, critical: true);
            var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
                new OidCollection() {
                    new Oid(
                        ServerAuthenticationEnhancedKeyUsageOid,
                        ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
                },
                critical: true);

            var basicConstraints = new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true);

            byte[] bytePayload;


            bytePayload = new byte[1];
            bytePayload[0] = (byte)AspNetHttpsCertificateVersion;

            var aspNetHttpsExtension = new X509Extension(
                new AsnEncodedData(
                    new Oid(AspNetHttpsOid, "ASP.NET Core HTTPS development certificate"),
                    bytePayload),
                critical: false);


            extensions.Add(basicConstraints);
            extensions.Add(keyUsage);
            extensions.Add(enhancedKeyUsage);
            extensions.Add(sanBuilder.Build(critical: true));
            extensions.Add(aspNetHttpsExtension);

            return CreateCertificate(ca, subject, extensions, notBefore, notAfter);
        }

        internal static X509Certificate2 CreateSelfSignedCertificate(
            X500DistinguishedName subject,
            IEnumerable<X509Extension> extensions,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter)
        {
            var key = CreateKeyMaterial(2048);

            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            foreach (var extension in extensions)
            {
                request.CertificateExtensions.Add(extension);
            }


            var result = request.CreateSelfSigned(notBefore, notAfter);
            return result;


            RSA CreateKeyMaterial(int minimumKeySize)
            {
                var rsa = RSA.Create(minimumKeySize);
                if (rsa.KeySize < minimumKeySize)
                {
                    throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
                }


                return rsa;
            }
        }

        internal static X509Certificate2 CreateCertificate(
            X509Certificate2 issuer,
            X500DistinguishedName subject,
            IEnumerable<X509Extension> extensions,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter)
        {
            var key = CreateKeyMaterial(2048);

            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            foreach (var extension in extensions)
            {
                request.CertificateExtensions.Add(extension);
            }

            var result = request.Create(issuer, notBefore, notAfter, Guid.NewGuid().ToByteArray());
            return result.CopyWithPrivateKey(key);

            RSA CreateKeyMaterial(int minimumKeySize)
            {
                var rsa = RSA.Create(minimumKeySize);
                if (rsa.KeySize < minimumKeySize)
                {
                    throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
                }


                return rsa;
            }
        }

    }
}
