using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security;
using System.Text;
using CryptoCore;

namespace CryptoCoreTests;

public static class Tests
{
    private static readonly string keyPairPath = @"rsaKeyPair.pem";
    private static readonly string privateKeyPath = @"rsaPrivateKey.pem";
    private static readonly string publicKeyPath = @"rsaPublicKey.pem";
    private static readonly string csrPath = @"rsaCSR.pem";
    private static readonly string signedCertPath = @"rsaSignedCert.pem";
    private static readonly string selfSignedCertPath = @"selfSignedCert.pem";
    private static readonly string privateCertPath = @"privateCert.pfx";
    private static readonly string password = "password";

    public static void TestCreateKeyPairRSA()
    {
        var keyPair = Crypto.CreateKeyPairRSA();
        keyPair.WriteKeyPairToPemFile(keyPairPath);

        if (keyPair.Public.IsRSAKey())
            Console.WriteLine("RSA key pair generation: success");

        else Console.WriteLine("RSA key pair generation: fail");

        Console.WriteLine();
    }


    public static void TestGenerateECDSAKeyPair()
    {
        var keyPair = Crypto.CreateKeyPairECDSA();
        keyPair.WriteKeyPairToPemFile(keyPairPath);

        if (keyPair.Public.IsECDSAKey())
            Console.WriteLine("ECDSA key pair generation: success");

        else Console.WriteLine("ECDSA key pair generation: fail");

        Console.WriteLine();
    }

    public static void TestWriteKeyPairInPemFile()
    {
        var keyPair = keyPairPath.GetKeyPairViaPemFile();
        keyPair.Private.WriteToPemFile(privateKeyPath);
        keyPair.Public.WriteToPemFile(publicKeyPath);

        if ((PemTools.GetPrivateKeyViaPemFile(privateKeyPath) != null) && (PemTools.GetPublicKeyViaPemFile(publicKeyPath) != null))
            Console.WriteLine("Writing key pair to PEM file: success");

        else Console.WriteLine("Writing key pair to PEM file: fail");

        Console.WriteLine();
    }

    public static void TestCreateSelfSignedCertificate()
    {
        var keyPair = keyPairPath.GetKeyPairViaPemFile();
        var csr = Crypto.CreateCertificationRequest("RU",
                                                    "Sverdlovdkaya_oblast",
                                                    "4_Turgeneva_street",
                                                    "Ural_Federal_University",
                                                    "Mathematics_mechanics_and_computer_science_department",
                                                    "Test_Name",
                                                    CryptoAlgorithms.SHA256withRSA,
                                                    keyPair);
        csr.WriteToPemFile(csrPath);

        var selfSignedCert = Crypto.CreateSelfSignedCertificate(csrPath.GetCertificationRequestViaPemFile(),
                                                         keyPairPath.GetPrivateKeyViaPemFile(),
                                                         DateTime.UtcNow,
                                                         DateTime.UtcNow.AddYears(1));
        selfSignedCert.WriteToPemFile(selfSignedCertPath);

        Console.WriteLine("Self signed certificate creation: ", selfSignedCertPath);
        Console.WriteLine();
    }

    public static void TestCreateSignedCertificate()
    {
        var signedCert = Crypto.CreateSignedCertificate(csrPath.GetCertificationRequestViaPemFile(),
                                                                privateCertPath.GetPrivateCertificateViaFile(password),
                                                                privateCertPath,
                                                                DateTime.UtcNow,
                                                                DateTime.UtcNow.AddYears(1));
        signedCert.WriteToPemFile(signedCertPath);

        Console.WriteLine("Signed certificate creation:", signedCertPath);
        Console.WriteLine();
    }

    public static void TestSignWithPrivateKey()
    {
        var content = "message";
        var signature = Crypto.SignWithPrivateKey(content, privateKeyPath.GetPrivateKeyViaPemFile());

        if (Crypto.VerifySignedByPublicKey(content, signature, publicKeyPath.GetPublicKeyViaPemFile()))
            Console.WriteLine("Signing with private key: success");
        else
            Console.WriteLine("Signing with private key: fail");

        Console.WriteLine();
    }

    public static void TestSignWithPrivateCertificate()
    {
        var content = "message";
        var signature = Crypto.SignWithPrivateCertificate(content, privateCertPath.GetPrivateCertificateViaFile(password));

        if (Crypto.VerifySignedDataByCertificateIssuer(signature, signedCertPath.GetPublicCertificateViaFile(), out var data))
        {
            if (data != null)
                Console.WriteLine(Encoding.UTF8.GetString(data));
        }

        else
        {
            Console.WriteLine("False");
        }
    }

    public static void TestEncryptAndDecryptWithCertificate()
    {
        var content = "message";
        var encoded = Crypto.EncryptWithPublicCertificate(content, signedCertPath.GetPublicCertificateViaFile());
        var decryptedContent = Crypto.DecryptWithPrivateCertificate(encoded, privateCertPath.GetPrivateCertificateViaFile(password), password);

        Console.WriteLine($"Decryption with certificate:\n    original content: \"{content}\"\n    decrypted content: \"{Encoding.UTF8.GetString(decryptedContent)}\"");
        Console.WriteLine();
    }

    public static void TestEncryptAndDecryptWithKey()
    {
        var content = "message";
        var keyPair = keyPairPath.GetKeyPairViaPemFile();
        var encoded = Crypto.EncryptWithPublicKey(content, keyPair.Public);
        var decryptedContent = Crypto.DecryptWithPrivateKey(encoded, keyPair.Private);

        Console.WriteLine($"Decryption with key:\n    original content: \"{content}\"\n    decrypted content: \"{decryptedContent}\"");
        Console.WriteLine();
    }

    public static void CreatePfx()
    {
        var certificate = new X509Certificate2(selfSignedCertPath);
        var keyPair = keyPairPath.GetKeyPairViaPemFile();

        var bcRsaPrivateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;
        var rsaParameters = DotNetUtilities.ToRSAParameters(bcRsaPrivateKey);
        var rsaKey = RSA.Create(rsaParameters);

        var exportableCertificate = certificate.CopyWithPrivateKey(rsaKey);

        var passwordForCertificateProtection = new SecureString();

        foreach (var @char in "password")
            passwordForCertificateProtection.AppendChar(@char);

        File.WriteAllBytes(privateCertPath, exportableCertificate.Export(X509ContentType.Pfx, passwordForCertificateProtection));
    }
}
