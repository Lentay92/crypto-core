using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using System.Security.Cryptography.X509Certificates;

namespace CryptoCoreTests;

public static class TestTools
{
    public static bool IsRSAKey(this AsymmetricKeyParameter key)
    {
        switch (key)
        {
            case RsaPrivateCrtKeyParameters:
            case RsaKeyParameters:
                return true;
            default:
                return false;
        }
    }

    public static bool IsRSAKey(this X509Certificate2 cert)
    {
        var keyAlgorithm = cert.PublicKey.Oid.FriendlyName;

        if (keyAlgorithm != null && keyAlgorithm.Contains("RSA"))
            return true;
        if (keyAlgorithm != null && (keyAlgorithm.Contains("ECDSA") || keyAlgorithm.Contains("ECDsa")))
            return false;

        throw new Exception("Unknown public key type");
    }

    public static bool IsECDSAKey(this AsymmetricKeyParameter key)
    {
        switch (key)
        {
            case ECPrivateKeyParameters:
            case ECPublicKeyParameters:
                return true;
            default:
                return false;
        }
    }

    public static bool IsECDSAKey(this X509Certificate2 cert)
    {
        var keyAlgorithm = cert.PublicKey.Oid.FriendlyName;

        if (keyAlgorithm != null && keyAlgorithm.Contains("RSA"))
            return false;
        if (keyAlgorithm != null && (keyAlgorithm.Contains("ECDSA") || keyAlgorithm.Contains("ECDsa")))
            return true;

        throw new Exception("Unknown public key type");
    }
}
