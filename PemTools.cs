using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;

namespace CryptoCore;

public static class PemTools
{
    public static void WriteToPemFile(this object data, string fileName)
    {
        using (var dataWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(dataWriter);
            pemWriter.WriteObject(data);
        }
    }

    public static void WriteKeyPairToPemFile(this AsymmetricCipherKeyPair key, string fileName)
    {
        using (var privateKeyWriter = new StreamWriter(fileName))
        {
            var pemWriter = new PemWriter(privateKeyWriter);
            pemWriter.WriteObject(key.Private);
            pemWriter.WriteObject(key.Public);
        }
    }

    public static Pkcs10CertificationRequest GetCertificationRequestViaPemFile(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (Pkcs10CertificationRequest)pemReader.ReadObject();
        }
    }

    public static AsymmetricCipherKeyPair GetKeyPairViaPemFile(this string pemFilePath)
    {
        using (var reader = new StreamReader(pemFilePath))
        {
            var pemReader = new PemReader(reader);
            return (AsymmetricCipherKeyPair)pemReader.ReadObject();
        }
    }

    public static AsymmetricKeyParameter GetPrivateKeyViaPemFile(this string privateKeyPath)
    {
        using (var reader = new StreamReader(privateKeyPath))
        {
            var pemReader = new PemReader(reader);
            var obj = pemReader.ReadObject();

            if (obj is AsymmetricCipherKeyPair keyPair)
                return keyPair.Private;

            throw new InvalidOperationException("The provided file does not contain a private key.");
        }
    }

    public static AsymmetricKeyParameter GetPublicKeyViaPemFile(this string publicKeyPath)
    {
        using (var reader = new StreamReader(publicKeyPath))
        {
            var pemReader = new PemReader(reader);
            var obj = pemReader.ReadObject();

            if (obj is RsaKeyParameters keyPair)
            {
                if (keyPair.IsPrivate)
                    throw new Exception("The provided file contain a private key instead of a public key.");

                return keyPair;
            }

            throw new InvalidOperationException("The provided file does not contain a public key.");
        }
    }
}
