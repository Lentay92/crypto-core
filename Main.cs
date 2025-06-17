using CryptoCoreTests;

Console.WriteLine("Starting tests...");
Console.WriteLine();

Tests.TestCreateKeyPairRSA();
Tests.TestWriteKeyPairInPemFile();
Tests.TestCreateSelfSignedCertificate();
Tests.CreatePfx();
Tests.TestCreateSignedCertificate();
Tests.TestEncryptAndDecryptWithCertificate();
Tests.TestEncryptAndDecryptWithKey();
Tests.TestSignWithPrivateKey();
Tests.TestSignWithPrivateCertificate();

