using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Linq;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CryptoCore;

public static class PfxTools
{
    public static AsymmetricKeyParameter GetPrivateKeyViaCertificatePfxFile(this string pfxPath, string? password)
    {
        var pfxCertificate = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        return pfxCertificate.GetPrivateKeyViaCertificate(password);
    }

    public static AsymmetricKeyParameter GetPrivateKeyViaCertificatePfxByteArray(this byte[] pfx, string? password)
    {
        var pfxCertificate = new X509Certificate2(pfx, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        return pfxCertificate.GetPrivateKeyViaCertificate(password);
    }

    public static AsymmetricKeyParameter GetPrivateKeyViaCertificate(this X509Certificate2 certificate, string? password)
    {
        AsymmetricKeyParameter? privateKey = null;

        try
        {
            privateKey = DotNetUtilities.GetKeyPair(certificate.GetRSAPrivateKey()).Private ?? DotNetUtilities.GetKeyPair(certificate.GetECDsaPrivateKey()).Private;
        }

        catch (Exception)
        {
            // ignored
        }

        if (privateKey is not null)
            return privateKey;

        try
        {
            var pkcs12Store = new Pkcs12StoreBuilder().Build();
            using (var pfxStream = new MemoryStream(certificate.Export(X509ContentType.Pkcs12)))
                pkcs12Store.Load(pfxStream, password == null ? "".ToCharArray() : password.ToCharArray());


            foreach (var alias in pkcs12Store.Aliases)
            {
                if (pkcs12Store.IsKeyEntry(alias))
                {
                    privateKey = pkcs12Store.GetKey(alias).Key;

                    break;
                }
            }

            if (privateKey == null)
                throw new InvalidOperationException("No private key found in this file.");
        }

        catch (Exception)
        {
            var rsa = certificate.GetRSAPrivateKey();

            if (rsa == null)
                throw new Exception("Root certificate error");

            using (var exportRewriter = RSA.Create())
            {
                exportRewriter.ImportEncryptedPkcs8PrivateKey(password,
                                                              rsa.ExportEncryptedPkcs8PrivateKey(password,
                                                                                                 new PbeParameters(PbeEncryptionAlgorithm.Aes128Cbc,
                                                                                                     HashAlgorithmName.SHA256,
                                                                                                     1)),
                                                              out var _);
                var asymmetricCipherKeyPair = DotNetUtilities.GetRsaKeyPair(exportRewriter.ExportParameters(true));

                return asymmetricCipherKeyPair.Private;
            }
        }

        return privateKey;
    }

    public static AsymmetricKeyParameter GetPublicKeyViaCertificatePfxFile(this string pfxPath, string? password)
    {
        var pfxCertificate = new X509Certificate2(pfxPath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        return pfxCertificate.GetPublicKeyViaCertificate(password);
    }

    public static AsymmetricKeyParameter GetPublicKeyViaCertificatePfxByteArray(this byte[] pfx, string? password)
    {
        var pfxCertificate = new X509Certificate2(pfx, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
        return pfxCertificate.GetPublicKeyViaCertificate(password);
    }

    public static AsymmetricKeyParameter GetPublicKeyViaCertificate(this X509Certificate2 certificate, string? password)
    {
        var pkcs12Store = new Pkcs12StoreBuilder().Build();
        using (var pfxStream = new MemoryStream(certificate.Export(X509ContentType.Pkcs12)))
            pkcs12Store.Load(pfxStream, password == null ? "".ToCharArray() : password.ToCharArray());

        var aliases = pkcs12Store.Aliases;
        var alias = aliases.FirstOrDefault(a => pkcs12Store.IsKeyEntry(a));

        X509CertificateEntry[] chain = pkcs12Store.GetCertificateChain(alias);

        return chain[0].Certificate.GetPublicKey();
    }
}
