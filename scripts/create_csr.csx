using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

if (!MLDsa.IsSupported) throw new NotSupportedException("ML-DSA is not supported on this platform.");


class MinimalDnInfo {
    /*      Properties      */
    string FQDN { get; set; }
    string Organization { get; set; }
    string Country { get; set; }
    string? State { get; set; } = string.Empty;
    string? Locality { get; set; } = string.Empty;

    /*      Constructors      */
    // Constructor that initializes the DN components with the provided values.
    public MinimalDnInfo(string _fqdn, string _organization, string _country, string _state, string _locality)
    {
        FQDN = _fqdn;
        Organization = _organization;
        Country = _country;
        State = _state;
        Locality = _locality;
    }

    // Constructor that prompts the user to enter the DN components interactively.
    public MinimalDnInfo()
    {
        Console.WriteLine("Enter the FQDN (i.e. Common Name/CN) for the certificate:");
        FQDN = Console.ReadLine();

        Console.WriteLine("Enter the Organization (O) for the certificate:");
        Organization = Console.ReadLine();

        Console.WriteLine("Enter the Country (C) for the certificate:");
        Country = Console.ReadLine();

        Console.WriteLine("Enter the State/Province (ST) for the certificate:");
        State = Console.ReadLine();

        Console.WriteLine("Enter the Locality (L) for the certificate:");
        Locality = Console.ReadLine();
    }

    /*      Methods      */
    // Constructs and prints the X500 distinguished name based on the provided DN components and returns it as an X500DistinguishedName object.
    public X500DistinguishedName PrintDn()
    {
        // Make builder for the distinguished name and add the relevant components
        X500DistinguishedNameBuilder x500Builder = new X500DistinguishedNameBuilder();
        x500Builder.AddCommonName(this.FQDN);
        x500Builder.AddOrganizationName(this.Organization);
        x500Builder.AddCountryName(this.Country);
        x500Builder.AddStateOrProvinceName(this.State);
        x500Builder.AddLocalityName(this.Locality);

        // Build the distinguished name from the components added to the builder
        X500DistinguishedName certificateDN = x500Builder.Build();
        Console.WriteLine($"Constructed Distinguished Name: {certificateDN.Name}");
        return certificateDN;
    }
}

MinimalDnInfo dnInfo = new MinimalDnInfo();
X500DistinguishedName subjectDN = dnInfo.PrintDn();

CertificateRequest certRequest;
using (RSA rsa = RSA.Create(4096))
{
    PublicKey publicKey = PublicKey.CreateFromSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo(), out _);

    HashAlgorithmName algorithmName = HashAlgorithmName.SHA256;
    using HashAlgorithm hashAlgorithm = algorithmName.Create();

    RSASignaturePadding rsaPadding = RSASignaturePadding.Pkcs1;

    certRequest = new CertificateRequest(
        subjectDN,
        rsa,
        algorithmName,
        rsaPadding
    );
}

class SanHelper
{
    /*      Properties      */
    private SubjectAlternativeNameBuilder _sanBuilder = new SubjectAlternativeNameBuilder();
    public X509Extension? sanNames { 
        get 
        { 
            return _sanBuilder.Build(); 
        } 
        set; 
    }

    /*      Constructor      */
    public SanHelper()
    {
        _sanBuilder = new SubjectAlternativeNameBuilder();
    }

    /*      Methods      */
    public void GetSanNames()
    {
        string sanDnsEntryPrompt = @"
        Enter a DNS SAN entry, if required.
        Press Enter without typing anything to move on to IP SAN entries.

        ";
        Console.WriteLine(sanDnsEntryPrompt);
        string sanDnsEntry = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(sanDnsEntry))
        {
            _sanBuilder.AddDnsName(sanDnsEntry);
        }

        string sanIpEntryPrompt = @"
        Enter an IP SAN entry, if required.
        Press Enter without typing anything to move on to URI SAN entries.

        ";
        Console.WriteLine(sanIpEntryPrompt);
        string sanIpEntry = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(sanIpEntry))
        {
            if (IPAddress.TryParse(sanIpEntry, out IPAddress ipAddress))
            {
                _sanBuilder.AddIpAddress(ipAddress);
            }
        }
        
        string sanUriEntryPrompt = @"
        Enter a URI SAN entry, if required.
        Press Enter without typing anything to finish entering SAN entries.

        ";
        Console.WriteLine(sanUriEntryPrompt);
        string sanUriEntry = Console.ReadLine();
        if (!string.IsNullOrWhiteSpace(sanUriEntry))
        {
            if (Uri.TryCreate(sanUriEntry, UriKind.Absolute, out Uri uri))
            {
                _sanBuilder.AddUri(uri);
            }
        }

        if ((sanDnsEntry = string.IsNullOrWhiteSpace(sanDnsEntry)) &&
            (sanIpEntry = string.IsNullOrWhiteSpace(sanIpEntry)) &&
            (sanUriEntry = string.IsNullOrWhiteSpace(sanUriEntry)))
        {
            Console.WriteLine("No SAN entries were provided. Moving on.");
        }

        else
        {
            sanNames = _sanBuilder.Build();
        }
    }    
}

SanHelper sanHelper = new SanHelper();
sanHelper.GetSanNames();
certRequest.CertificateExtensions.Add(sanHelper.sanNames);
string pkiDirectory = @"C:\pki\";
string keysBaseDirectory = @"C:\pki\keys\";
string privateKeysDirectory = @"C:\pki\keys\private\";
string publicKeysDirectory = @"C:\pki\keys\public\";
string certsDirectory = @"C:\pki\certs\";
string certificatesDirectory = @"C:\pki\certs\certificates\";
string csrOutputDirectory = @"C:\pki\certs\certificate_requests\";
string caOutputDirectory = @"C:\pki\certs\certificate_authorities\";
SortedSet<string> directoriesToCreate = new SortedSet<string>
{
    pkiDirectory,
    keysBaseDirectory,
    privateKeysDirectory,
    publicKeysDirectory,
    certsDirectory,
    certificatesDirectory,
    csrOutputDirectory,
    caOutputDirectory
};
foreach (string directory in directoriesToCreate)
{
    if (!Directory.Exists(directory))
    {
        Directory.CreateDirectory(directory);
        Console.WriteLine($"Created directory: {directory}");
    }
    else
    {
        Console.WriteLine($"Directory already exists: {directory}");
    }
}

string csrFileName = $"{subjectDN.CommonName}_CertificateRequest.csr";
string csrFilePath = Path.Combine(csrOutputDirectory, csrFileName);

Console.WriteLine($"Saving CSR to: {csrFilePath}");
try
{
    File.WriteAllBytes(csrFilePath, certRequest.CreateSigningRequest());
    Console.WriteLine($"CSR saved successfully to: {csrFilePath}. Exiting.");
}
catch (Exception ex)
{
    Console.WriteLine($"An error occurred while saving the CSR: {ex.Message}");
}