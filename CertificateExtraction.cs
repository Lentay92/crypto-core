using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoCore;

public static class CertificfateExtraction
{

    public static X509Certificate2 GetPrivateCertificateViaFile(this string certFilePath, string? password)
    {
        return new X509Certificate2(certFilePath, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 GetPrivateCertificateViaByteArray(this byte[] cert, string? password)
    {
        return new X509Certificate2(cert, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 GetPrivateCertificateViaBase64String(this string base64PrivateKey, string password)
    {
        return new X509Certificate2(Convert.FromBase64String(base64PrivateKey), password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    public static X509Certificate2 GetPublicCertificateViaFile(this string certFilePath)
    {
        return new X509Certificate2(certFilePath);
    }

    public static X509Certificate2 GetPublicCertificateViaByteArray(this byte[] cert)
    {
        return new X509Certificate2(cert);
    }

    public static X509Certificate2 GetPublicCertificateViaBase64String(this string base64String)
    {
        return new X509Certificate2(Encoding.UTF8.GetBytes(base64String));
    }
}
