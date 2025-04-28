# Griffin HTTP Message Signatures

Code examples and utilities for implementing Griffin's HTTP message signatures and webhook verification. This repository contains sample implementations for signing API requests and verifying incoming webhooks in multiple programming languages.

## Overview

Griffin uses [HTTP Message Signatures](https://datatracker.ietf.org/doc/html/rfc9421) to:

1. **Verify client API requests** - Customers sign their API requests to Griffin

## Contents

- [Getting Started](#getting-started)
- [API HTTP Message signatures](#api-http-message-signatures)
- [Language Examples](#language-examples)
- [Resources](#resources)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

## Getting Started

To use the Griffin API securely:

1. Generate an Ed25519 key pair
2. Register your public key with Griffin via the [app](https://app.griffin.com/)
3. Sign your API requests using your private key

## API HTTP Message signatures

For detailed implementation instructions, see the [Griffin documentation on message signatures](https://docs.griffin.com/docs/guides/how-to-create-message-signatures).

## Language Examples

This repository contains example implementations in various programming languages:

- [Python](./python/) - Using the `http-message-signatures` library
- [Golang](./golang/) - Using [github.com/yaronf/httpsign](https://github.com/yaronf/httpsign)


## Resources

- [Griffin API Documentation](https://docs.griffin.com/docs/introduction/get-started-with-the-api)
- [Message Signatures Guide](https://docs.griffin.com/docs/guides/how-to-create-message-signatures)
- [HTTP Message Signatures Specification](https://datatracker.ietf.org/doc/html/rfc9421)

## Contributing

Contributions are welcome! If you have improvements or additional language examples, please submit a pull request.

## Disclaimer

> [!IMPORTANT]
> The external libraries used in these examples have not undergone a thorough security review by Griffin. While we provide these examples for convenience, we do not endorse any third-party libraries and are not liable for any security issues or bugs they may contain. You should conduct your own review of any libraries before using them in production.

## License

[EPL 2.0 License](LICENSE.txt)