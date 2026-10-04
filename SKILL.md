---
title: create-certificate-request
description: "This skill creates a certificate request using C#."
license: MIT
compatibility: Requires .NET 10.
metadata: 
  author: Zack Polozune
  version: 1.0.0
  date: 2026-10-05
---
# Skill Instructions
1. Get the necessary information for the certificate request, including the FQDN, organization, country, state/province, and locality.
2. Create the distinguished name (DN) string for the certificate using the collected information.
3. Generate an ML-DSA-87 key pair.
4. Export the public key from the generated key pair.
5. Create a certificate request using the distinguished name and the public key.
6. Sign the certificate request with the private key.
7. Save the certificate request to a file named after the FQDN with a `.csr` extension.
8. Confirm that the CSR file has been successfully created and contains the expected information.
9. Inform the user the process is complete and print the location of the saved CSR file.