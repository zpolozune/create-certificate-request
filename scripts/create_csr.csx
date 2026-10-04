using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

if (!MLDsa.IsSupported) throw new NotSupportedException("ML-DSA is not supported on this platform.");

using (var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87))
{
    var publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(key.ExportSubjectPublicKeyInfo(), out _);
}

Console.WriteLine("Enter the FQDN (i.e. Common Name/CN) for the certificate:");
var fqdn = Console.ReadLine();

Console.WriteLine("Enter the Organization (O) for the certificate:");
var organization = Console.ReadLine();

Console.WriteLine("Enter the Country (C) for the certificate:");
var country = Console.ReadLine();

Console.WriteLine("Enter the State/Province (ST) for the certificate:");
var state = Console.ReadLine();

Console.WriteLine("Enter the Locality (L) for the certificate:");
var locality = Console.ReadLine();

var certDN = $"CN={fqdn}, O={organization}, C={country}, ST={state}, L={locality}"; 

var req = new CertificateRequest(
    new X500DistinguishedName(certDN),
    publicKey,
    HashAlgorithmName.SHA256
    );

var generate = X509SignatureGenerator.CreateForMLDsa(key);
File.WriteAllBytes($"{fqdn}.csr", req.CreateSigningRequest(generate));
Console.WriteLine($"CSR for {fqdn} has been created and saved as {fqdn}.csr");