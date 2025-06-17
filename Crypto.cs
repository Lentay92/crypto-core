using System;
using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace CryptoCore;

public static class Crypto
{
    public static AsymmetricCipherKeyPair CreateKeyPairRSA(int keySize = 2048)
    {
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), keySize);
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(keyGenerationParameters);

        return keyPairGenerator.GenerateKeyPair();
    }

    public static AsymmetricCipherKeyPair CreateKeyPairECDSA(EllipticCurveTypes algoritm = EllipticCurveTypes.secp256k1)
    {
        var curve = ECNamedCurveTable.GetByName(algoritm.ToString());
        var domainParameters = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var keyGenerationParameters = new ECKeyGenerationParameters(domainParameters, new SecureRandom());
        var generator = new ECKeyPairGenerator();
        generator.Init(keyGenerationParameters);

        return generator.GenerateKeyPair();
    }

    public static Pkcs10CertificationRequest CreateCertificationRequest(string country,
                                                                        string state,
                                                                        string locality,
                                                                        string organization,
                                                                        string organizationalUnit,
                                                                        string commonName,
                                                                        CryptoAlgorithms algorithm,
                                                                        AsymmetricCipherKeyPair keyPair)
    {
        var subject = new X509Name($"C={country}, ST={state}, L={locality}, O={organization}, OU={organizationalUnit}, CN={commonName}");

        var algorithmName = algorithm.ToString();

        var isRSA = algorithmName.IsRsaAlgorithm();

        var csr = keyPair.Private switch
        {
            ECPrivateKeyParameters when !isRSA => new Pkcs10CertificationRequest(algorithmName, subject, keyPair.Public, null, keyPair.Private),
            RsaPrivateCrtKeyParameters when isRSA => new Pkcs10CertificationRequest(algorithmName, subject, keyPair.Public, null, keyPair.Private),
            _ => throw new Exception("Unknown key pair type")
        };

        return csr;
    }

    public static X509Certificate CreateSelfSignedCertificate(Pkcs10CertificationRequest csr,
                                                              AsymmetricKeyParameter privateKey,
                                                              DateTime startDate,
                                                              DateTime endDate,
                                                              CryptoAlgorithms algorithm = CryptoAlgorithms.SHA256withRSA)
    {
        var csrInfo = csr.GetCertificationRequestInfo();
        var certGenerator = new X509V3CertificateGenerator();
        var randomGenerator = new CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(csrInfo.Subject);
        certGenerator.SetNotBefore(startDate);
        certGenerator.SetNotAfter(endDate);
        certGenerator.SetSubjectDN(csrInfo.Subject);
        certGenerator.SetPublicKey(csr.GetPublicKey());

        certGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(csr.GetPublicKey()));

        ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm.ToString(), privateKey);

        return certGenerator.Generate(signatureFactory);
    }

    public static X509Certificate CreateSignedCertificate(Pkcs10CertificationRequest csr,
                                                            X509Certificate2 pfx,
                                                            string? pfxPassword,
                                                            DateTime startDate,
                                                            DateTime endDate,
                                                            CryptoAlgorithms algorithm = CryptoAlgorithms.SHA256withRSA)
    {
        AsymmetricKeyParameter pfxPrivateKey;

        try
        {
            pfxPrivateKey = DotNetUtilities.GetKeyPair(pfx.GetRSAPrivateKey()).Private ?? DotNetUtilities.GetKeyPair(pfx.GetECDsaPrivateKey()).Private;
        }

        catch (Exception)
        {
            pfxPrivateKey = pfx.GetPrivateKeyViaCertificate(pfxPassword);
        }

        var pfxBouncyCastleCertificate = DotNetUtilities.FromX509Certificate(pfx);

        var csrInfo = csr.GetCertificationRequestInfo();
        var certGenerator = new X509V3CertificateGenerator();

        var randomGenerator = new CryptoApiRandomGenerator();
        var random = new SecureRandom(randomGenerator);
        var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);

        certGenerator.SetSerialNumber(serialNumber);
        certGenerator.SetIssuerDN(pfxBouncyCastleCertificate.SubjectDN);
        certGenerator.SetNotBefore(startDate);
        certGenerator.SetNotAfter(endDate);
        certGenerator.SetSubjectDN(csrInfo.Subject);
        certGenerator.SetPublicKey(csr.GetPublicKey());

        certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, false, new BasicConstraints(false));
        certGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier.Id, false, new SubjectKeyIdentifierStructure(csr.GetPublicKey()));

        ISignatureFactory signatureFactory = new Asn1SignatureFactory(algorithm.ToString(), pfxPrivateKey);

        return certGenerator.Generate(signatureFactory);
    }

    /// <summary>
    /// ------------------------------------------------------------<publicCertEncrypt>------------------------------------------------------------
    /// </summary>

    public static byte[] EncryptWithPublicCertificate(byte[] data, byte[] publicCert)
    {
        return EncryptWithPublicCertificate(data, publicCert.GetPublicCertificateViaByteArray());
    }

    public static byte[] EncryptWithPublicCertificate(byte[] data, string publicCertPath)
    {
        return EncryptWithPublicCertificate(data, publicCertPath.GetPublicCertificateViaFile());
    }

    public static byte[] EncryptWithPublicCertificate(string data, X509Certificate2 publicCert)
    {
        return EncryptWithPublicCertificate(Encoding.UTF8.GetBytes(data), publicCert);
    }

    public static byte[] EncryptWithPublicCertificate(byte[] data, X509Certificate2 publicCert)
    {
        var envelopGenerator = new CmsEnvelopedDataGenerator();
        var cert = new X509CertificateParser().ReadCertificate(publicCert.RawData);
        envelopGenerator.AddKeyTransRecipient(cert);

        return envelopGenerator.Generate(new CmsProcessableByteArray(data), CmsEnvelopedGenerator.DesEde3Cbc).GetEncoded();
    }

    /// <summary>
    /// ------------------------------------------------------------</publicCertEncrypt>------------------------------------------------------------
    /// </summary>

    /// <summary>
    /// ------------------------------------------------------------<privateCertDecrypt>------------------------------------------------------------
    /// </summary>

    public static byte[] DecryptWithPrivateCertificate(byte[] encryptedData, byte[] privateCert, string? password)
    {
        return DecryptWithPrivateCertificate(encryptedData, privateCert.GetPrivateCertificateViaByteArray(password), password);
    }

    public static byte[] DecryptWithPrivateCertificate(byte[] encryptedData, string privateCertPath, string? password)
    {
        return DecryptWithPrivateCertificate(encryptedData, privateCertPath.GetPrivateCertificateViaFile(password), password);
    }

    public static byte[] DecryptWithPrivateCertificate(string base64Data, byte[] privateCert, string? password)
    {
        return DecryptWithPrivateCertificate(Convert.FromBase64String(base64Data), privateCert.GetPrivateCertificateViaByteArray(password), password);
    }

    public static byte[] DecryptWithPrivateCertificate(string base64Data, string privateCertPath, string? password)
    {
        return DecryptWithPrivateCertificate(Convert.FromBase64String(base64Data), privateCertPath.GetPrivateCertificateViaFile(password), password);
    }

    public static byte[] DecryptWithPrivateCertificate(string base64Data, X509Certificate2 privateCert, string? password)
    {
        return DecryptWithPrivateCertificate(Convert.FromBase64String(base64Data), privateCert, password);
    }

    public static byte[] DecryptWithPrivateCertificate(byte[] encryptedData, X509Certificate2 privateCert, string? password)
    {
        AsymmetricKeyParameter key;

        try
        {
            key = DotNetUtilities.GetKeyPair(privateCert.GetRSAPrivateKey()).Private ?? DotNetUtilities.GetKeyPair(privateCert.GetECDsaPrivateKey()).Private;
        }

        catch (Exception)
        {
            key = privateCert.GetPrivateKeyViaCertificate(password);
        }

        var x509Certificate = DotNetUtilities.FromX509Certificate(privateCert);

        var recipientInfos = new CmsEnvelopedData(encryptedData).GetRecipientInfos();

        RecipientInformation? firstRecipient = null;

        foreach (var recipientInfo in recipientInfos.GetRecipients())
        {
            if (recipientInfo.RecipientID.Issuer.Equivalent(x509Certificate.IssuerDN) || recipientInfo.RecipientID.SerialNumber.Equals(x509Certificate.SerialNumber))
                firstRecipient = recipientInfo;
        }

        return firstRecipient!.GetContent(key);
    }

    /// <summary>
    /// ------------------------------------------------------------</privateCertDecrypt>------------------------------------------------------------
    /// </summary>

    public static string EncryptWithPublicKey(string plaintext, AsymmetricKeyParameter publicKey)
    {
        var encryptEngine = new Pkcs1Encoding(new RsaEngine());
        encryptEngine.Init(true, publicKey);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var encryptedBytes = encryptEngine.ProcessBlock(plaintextBytes, 0, plaintextBytes.Length);

        return Convert.ToBase64String(encryptedBytes);
    }

    public static string DecryptWithPrivateKey(string ciphertext, AsymmetricKeyParameter privateKey)
    {
        var decryptEngine = new Pkcs1Encoding(new RsaEngine());
        decryptEngine.Init(false, privateKey);
        var ciphertextBytes = Convert.FromBase64String(ciphertext);
        var decryptedBytes = decryptEngine.ProcessBlock(ciphertextBytes, 0, ciphertextBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }

    /// <summary>
    /// ------------------------------------------------------------<privateCertSign>------------------------------------------------------------
    /// </summary>

    public static byte[] SignWithPrivateCertificate(byte[] data, byte[] privateCert, string? password)
    {
        return SignWithPrivateCertificate(data, privateCert.GetPrivateCertificateViaByteArray(password));
    }

    public static byte[] SignWithPrivateCertificate(byte[] data, string privateCertPath, string? password)
    {
        return SignWithPrivateCertificate(data, privateCertPath.GetPrivateCertificateViaFile(password));
    }

    public static byte[] SignWithPrivateCertificate(string base64Data, byte[] privateCert, string? password)
    {
        return SignWithPrivateCertificate(Encoding.UTF8.GetBytes(base64Data), privateCert.GetPrivateCertificateViaByteArray(password));
    }

    public static byte[] SignWithPrivateCertificate(string base64Data, string privateCertPath, string? password)
    {
        return SignWithPrivateCertificate(Encoding.UTF8.GetBytes(base64Data), privateCertPath.GetPrivateCertificateViaBase64String(password));
    }

    public static byte[] SignWithPrivateCertificate(string base64Data, X509Certificate2 privateKeyCert)
    {
        return SignWithPrivateCertificate(Encoding.UTF8.GetBytes(base64Data), privateKeyCert);
    }

    public static byte[] SignWithPrivateCertificate(byte[] data, X509Certificate2 privateKeyCert)
    {
        if (data == null)
            throw new ArgumentNullException(nameof(data));

        if (privateKeyCert == null)
            throw new ArgumentNullException(nameof(privateKeyCert));

        var signedCms = new SignedCms(new ContentInfo(data));
        signedCms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, privateKeyCert));

        return signedCms.Encode();
    }

    /// <summary>
    /// ------------------------------------------------------------</privateCertSign>------------------------------------------------------------
    /// </summary>



    /// <summary>
    /// ------------------------------------------------------------<privateKeySign>------------------------------------------------------------
    /// </summary>

    public static byte[] SignWithPrivateKey(byte[] data, byte[] privateCert, string? password)
    {
        return SignWithPrivateKey(data, privateCert.GetPrivateKeyViaCertificatePfxByteArray(password));
    }

    public static byte[] SignWithPrivateKey(byte[] data, string privateCertPath, string? password)
    {
        return SignWithPrivateKey(data, privateCertPath.GetPrivateKeyViaCertificatePfxFile(password));
    }

    public static byte[] SignWithPrivateKey(string data, byte[] privateCert, string? password)
    {
        return SignWithPrivateKey(Encoding.UTF8.GetBytes(data), privateCert.GetPrivateKeyViaCertificatePfxByteArray(password));
    }

    public static byte[] SignWithPrivateKey(string data, string privateCertPath, string? password)
    {
        return SignWithPrivateKey(Encoding.UTF8.GetBytes(data), privateCertPath.GetPrivateKeyViaCertificatePfxFile(password));
    }

    public static byte[] SignWithPrivateKey(string data, string privateKeyPath)
    {
        return SignWithPrivateKey(Encoding.UTF8.GetBytes(data), privateKeyPath.GetKeyPairViaPemFile().Private);
    }

    public static byte[] SignWithPrivateKey(byte[] data, string privateKeyPath)
    {
        return SignWithPrivateKey(data, privateKeyPath.GetKeyPairViaPemFile().Private);
    }

    public static byte[] SignWithPrivateKey(string data, AsymmetricKeyParameter privateKey)
    {
        return SignWithPrivateKey(Encoding.UTF8.GetBytes(data), privateKey);
    }

    public static byte[] SignWithPrivateKey(byte[] data, AsymmetricKeyParameter privateKey, CryptoAlgorithms algorithm = CryptoAlgorithms.SHA256withRSA)
    {
        var signer = SignerUtilities.GetSigner(algorithm.ToString());
        signer.Init(true, privateKey);

        signer.BlockUpdate(data, 0, data.Length);

        return signer.GenerateSignature();
    }

    /// <summary>
    /// ------------------------------------------------------------</privateKeySign>------------------------------------------------------------
    /// </summary>

    public static bool VerifySignedDataByCertificateIssuer(byte[] signature, X509Certificate2 publicCert, out byte[]? decodedMessage)
    {
        bool isValid;
        decodedMessage = null;

        if (signature == null)
            throw new ArgumentNullException(nameof(signature));

        if (publicCert == null)
            throw new ArgumentNullException(nameof(publicCert));

        var signedCms = new SignedCms();

        try
        {
            signedCms.Decode(signature);
            signedCms.CheckSignature(new X509Certificate2Collection(publicCert), false);
            decodedMessage = signedCms.ContentInfo.Content;

            var signer = signedCms.SignerInfos[0];
            var signingCert = signer.Certificate;

            if (signingCert is null)
                throw new Exception("Not found certificate from sigendData");

            if (signingCert.Subject == publicCert.Issuer && signingCert.Issuer == publicCert.Issuer)
            {
                isValid = true;
            }

            else
            {
                isValid = false;
                Console.WriteLine("The message was signed by a different certificate.");
            }
        }

        catch (CryptographicException)
        {
            isValid = false;
        }

        return isValid;
    }

    public static bool VerifySignedByPublicKey(string message,
                                               byte[] sigendData,
                                               AsymmetricKeyParameter publicKey,
                                               CryptoAlgorithms algorithm = CryptoAlgorithms.SHA256withRSA)
    {
        var verifier = SignerUtilities.GetSigner(algorithm.ToString());
        verifier.Init(false, publicKey);

        var messageBytes = Encoding.UTF8.GetBytes(message);
        verifier.BlockUpdate(messageBytes, 0, messageBytes.Length);

        return verifier.VerifySignature(sigendData);
    }

    public static bool IsRsaAlgorithm(this CryptoAlgorithms algorithm)
    {
        var algorithmName = algorithm.ToString();

        return algorithmName[^3..].ToLower() == "rsa";
    }

    public static bool IsRsaAlgorithm(this string algorithmName)
    {
        return algorithmName[^3..].ToLower() == "rsa";
    }

    public static bool IsECDSAAlgorithm(this CryptoAlgorithms algorithm)
    {
        var algorithmName = algorithm.ToString();

        return algorithmName[^5..].ToLower() == "ecdsa";
    }

    public static bool IsECDSAAlgorithm(this string algorithmName)
    {
        return algorithmName[^5..].ToLower() == "ecdsa";
    }
}

