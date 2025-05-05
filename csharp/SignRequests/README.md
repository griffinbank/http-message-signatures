# Griffin API Request Signing - C# Example

This example demonstrates how to sign API requests to Griffin using C# and the Bouncy Castle library for Ed25519 cryptography support.

## Prerequisites

- .NET 6.0 or later
- An API key from Griffin
- An Ed25519 key pair registered with Griffin
- Bouncy Castle NuGet package for Ed25519 support

## Generating an Ed25519 Key Pair

You can generate an Ed25519 key pair using the `openssl` command:

```bash
openssl genpkey -algorithm ed25519 -out private_key.pem -outpubkey public_key.pem
```

Follow our [documentation](https://docs.griffin.com/docs/guides/how-to-create-message-signatures/) for a step by step on registering your public key.

> [!IMPORTANT]  
> Store your private key securely and protect it from unauthorized access.
> Check out [Griffin's recommended security practices](https://docs.griffin.com/docs/introduction/api-security-overview/index.html#recommended-security-practices).

## Setup

1. Install the required NuGet packages:

```bash
dotnet add package Portable.BouncyCastle
```

2. Set the required environment variables:

```bash
export GRIFFIN_API_KEY="your_api_key"
export GRIFFIN_KEY_ID="your_key_id"
```

3. Place your `private_key.pem` file in the project directory.

## Implementation Overview

The example consists of several classes:

- `HttpSignatureHandler`: Core class implementing RFC 9421 HTTP Message Signatures
- `HttpSignatureClientHandler`: HTTP client handler that automatically signs outgoing requests
- `HttpClientExtensions`: Extension methods to easily configure an HTTP client with signature support
- `SignatureExample`: Sample usage demonstrating how to use the signing functionality

## Key Features

- Ed25519 signature generation compliant with RFC 9421
- Content digest calculation using SHA-512
- Support for all standard HTTP Message Signature components
- Automatic request signing with customizable signature expiration
- PEM key loading from file or environment variables

## Running the Example

To run the example:

```bash
dotnet run
```

This will:
1. Load your Ed25519 private key from `private_key.pem`
2. Create and sign a request to Griffin's message signature verification endpoint
3. Print the response and request headers for debugging

## Troubleshooting

If you encounter errors:

- Check that your environment variables are set correctly
- Ensure your private key is a valid Ed25519 key in PEM format
- Verify that your key ID matches the one registered with Griffin
- Check the request headers in the debug output to ensure they're formatted correctly
- Make sure the `Content-Type` header is set properly on your requests
- Verify that all required components are being signed

## Disclaimer

> [!IMPORTANT]
> The external libraries used in this example (such as Bouncy Castle) have not undergone a thorough security review by Griffin. While we provide these examples for convenience, we do not endorse any third-party libraries and are not liable for any security issues or bugs they may contain. You should conduct your own review of any libraries before using them in production.

## Additional Resources

- [Griffin's API Documentation](https://docs.griffin.com/docs/introduction/get-started-with-the-api)
- [Griffin's Message Signatures guide](https://docs.griffin.com/docs/guides/how-to-create-message-signatures)
- [Griffin's API Security guide](https://docs.griffin.com/docs/introduction/api-security-overview)
- [Bouncy Castle Documentation](https://www.bouncycastle.org/csharp/index.html)