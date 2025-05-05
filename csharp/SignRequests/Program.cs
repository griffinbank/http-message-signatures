using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

// Bouncy Castle imports for Ed25519 support
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace SignRequests
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("HTTP Message Signatures Example with Ed25519");
            await SignatureExample.Run();
        }
    }

    /// <summary>
    /// Implementation of HTTP Message Signatures as defined in RFC 9421
    /// </summary>
    public class HttpSignatureHandler
    {
        private readonly Ed25519PrivateKeyParameters _privateKey;
        private readonly string _keyId;
        private readonly TimeSpan _signatureExpiration;
        private readonly List<string> _componentsToSign;

        // Define default components to sign
        private static readonly List<string> DefaultComponentsToSign = new List<string>
        {
            "@method",
            "@target-uri",
            "@authority",
            "content-type",
            "content-digest"
        };

        /// <summary>
        /// Initializes a new instance of HttpSignatureHandler with Ed25519 key pair
        /// </summary>
        public HttpSignatureHandler(
            byte[] privateKeyBytes,
            string keyId,
            TimeSpan signatureExpiration,
            List<string> componentsToSign = null)
        {
            _privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
            _keyId = keyId ?? throw new ArgumentNullException(nameof(keyId));
            _signatureExpiration = signatureExpiration;
            _componentsToSign = componentsToSign ?? DefaultComponentsToSign;
        }

        /// <summary>
        /// Helper method to extract raw Ed25519 private key from PEM PKCS#8 format
        /// </summary>
        public static byte[] ExtractPrivateKeyFromPem(string pemKey)
        {
            using var pemReader = new PemReader(new StringReader(pemKey));
            object keyObject = pemReader.ReadObject();

            // Handle Ed25519 key formats
            if (keyObject is AsymmetricCipherKeyPair keyPair && 
                keyPair.Private is Ed25519PrivateKeyParameters ed25519KeyFromPair)
            {
                return ed25519KeyFromPair.GetEncoded();
            }
            else if (keyObject is Ed25519PrivateKeyParameters ed25519DirectKey)
            {
                return ed25519DirectKey.GetEncoded();
            }

            throw new Exception("Not a valid Ed25519 private key");
        }

        /// <summary>
        /// Signs an HTTP request according to RFC 9421
        /// </summary>
        public async Task SignRequest(HttpRequestMessage request)
        {
            // Calculate and add content digest if not already present
            if (!request.Headers.Contains("Content-Digest") && request.Content != null)
            {
                await AddContentDigestHeader(request);
            }

            // Generate signing metadata
            var signingMetadata = GenerateSigningMetadata();
            
            // Create the signature base
            string signatureBase = await CreateSignatureBase(request, signingMetadata);
            Console.WriteLine("\nSignature Base:");
            Console.WriteLine(signatureBase);

            // Generate the signature
            string signature = SignData(signatureBase);
            Console.WriteLine($"Raw signature (base64): {signature}");

            // Create the headers
            (string signatureInputValue, string signatureValue) = CreateSignatureHeaders(
                signingMetadata, signature);

            // Add headers to the request
            request.Headers.TryAddWithoutValidation("Signature-Input", signatureInputValue);
            request.Headers.TryAddWithoutValidation("Signature", signatureValue);
        }

        /// <summary>
        /// Generates metadata needed for signing (timestamps and nonce)
        /// </summary>
        private SigningMetadata GenerateSigningMetadata()
        {
            return new SigningMetadata
            {
                Created = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Expires = DateTimeOffset.UtcNow.Add(_signatureExpiration).ToUnixTimeSeconds(),
                Nonce = Guid.NewGuid().ToString()
            };
        }

        /// <summary>
        /// Creates headers for HTTP signatures
        /// </summary>
        private (string SignatureInput, string Signature) CreateSignatureHeaders(
            SigningMetadata metadata, string signature)
        {
            string componentsString = string.Join(" ", _componentsToSign.Select(c => $"\"{c}\""));
            
            string signatureInputValue = 
                $"sig1=({componentsString});keyid=\"{_keyId}\";alg=\"ed25519\";" +
                $"created={metadata.Created};expires={metadata.Expires};nonce=\"{metadata.Nonce}\"";
            
            string signatureValue = $"sig1=:{signature}:";
            
            Console.WriteLine($"Signature-Input: {signatureInputValue}");
            Console.WriteLine($"Signature: {signatureValue}");
            
            return (signatureInputValue, signatureValue);
        }

        /// <summary>
        /// Creates the signature base for signing
        /// </summary>
        private async Task<string> CreateSignatureBase(
            HttpRequestMessage request, SigningMetadata metadata)
        {
            var signatureBaseComponents = new StringBuilder();

            foreach (var component in _componentsToSign)
            {
                string value = await GetComponentValue(component, request);
                // Use LF line endings (not CRLF)
                signatureBaseComponents.Append($"\"{component}\": {value}\n");
            }

            // Add signature parameters
            signatureBaseComponents.Append(
                $"\"@signature-params\": ({string.Join(" ", _componentsToSign.Select(c => $"\"{c}\""))});" +
                $"keyid=\"{_keyId}\";alg=\"ed25519\";created={metadata.Created};" +
                $"expires={metadata.Expires};nonce=\"{metadata.Nonce}\"");

            return signatureBaseComponents.ToString();
        }

        /// <summary>
        /// Gets the value for a specific component from the HTTP request
        /// </summary>
        private async Task<string> GetComponentValue(string component, HttpRequestMessage request)
        {
            switch (component)
            {
                case "@method":
                    return request.Method.Method.ToUpper();

                case "@target-uri":
                    return request.RequestUri.ToString();

                case "@authority":
                    return request.RequestUri.Authority;

                case "@scheme":
                    return request.RequestUri.Scheme;

                case "@path":
                    return request.RequestUri.AbsolutePath;

                case "@query":
                    return request.RequestUri.Query.TrimStart('?');

                case "date":
                    if (!request.Headers.Contains("Date"))
                    {
                        request.Headers.Date = DateTimeOffset.UtcNow;
                    }
                    return request.Headers.Date?.ToString("r") ?? string.Empty;

                case "content-length":
                    if (request.Content != null)
                    {
                        long? length = request.Content.Headers.ContentLength;
                        if (length.HasValue)
                        {
                            return length.Value.ToString();
                        }
                        else
                        {
                            byte[] contentBytes = await request.Content.ReadAsByteArrayAsync();
                            request.Content.Headers.ContentLength = contentBytes.Length;
                            return contentBytes.Length.ToString();
                        }
                    }
                    return "0";

                case "content-type":
                    return request.Content?.Headers.ContentType?.ToString() ?? string.Empty;

                case "content-digest":
                    var contentDigestHeader = request.Headers.FirstOrDefault(h =>
                        string.Equals(h.Key, "Content-Digest", StringComparison.OrdinalIgnoreCase));
                    return contentDigestHeader.Value?.FirstOrDefault() ?? string.Empty;

                default:
                    // Regular HTTP header
                    if (request.Headers.TryGetValues(component, out var values))
                    {
                        return string.Join(", ", values);
                    }
                    else if (request.Content?.Headers.TryGetValues(component, out var contentValues) == true)
                    {
                        return string.Join(", ", contentValues);
                    }
                    return string.Empty;
            }
        }

        /// <summary>
        /// Adds Content-Digest header to the request
        /// </summary>
        public async Task AddContentDigestHeader(HttpRequestMessage request)
        {
            if (request.Content == null)
                return;

            byte[] contentBytes = await GetRequestContentBytes(request);
            string contentDigestValue = GenerateContentDigest(contentBytes);
            
            request.Headers.TryAddWithoutValidation("Content-Digest", contentDigestValue);
            
            Console.WriteLine($"Added Content-Digest header: {contentDigestValue}");
            Console.WriteLine($"Content bytes length: {contentBytes.Length}");
            Console.WriteLine($"Content as string: {Encoding.UTF8.GetString(contentBytes)}");
        }

        /// <summary>
        /// Gets the raw bytes from request content
        /// </summary>
        private async Task<byte[]> GetRequestContentBytes(HttpRequestMessage request)
        {
            // If it's ByteArrayContent, get the bytes directly to avoid any transformation
            if (request.Content is ByteArrayContent)
            {
                return await request.Content.ReadAsByteArrayAsync();
            }
            
            // For other content types, read as string and convert to bytes
            string contentString = await request.Content.ReadAsStringAsync();
            return Encoding.UTF8.GetBytes(contentString);
        }

        /// <summary>
        /// Generates a content digest using SHA-512
        /// </summary>
        private string GenerateContentDigest(byte[] contentBytes)
        {
            byte[] hash = SHA512.HashData(contentBytes);
            return $"sha-512=:{Convert.ToBase64String(hash)}:";
        }

        /// <summary>
        /// Signs the signature base using Ed25519
        /// </summary>
        private string SignData(string data)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(data);

            // Create Ed25519 signer and sign the data
            var signer = new Ed25519Signer();
            signer.Init(true, _privateKey);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            byte[] signature = signer.GenerateSignature();

            return Convert.ToBase64String(signature);
        }
    }

    /// <summary>
    /// Metadata for signature generation
    /// </summary>
    public class SigningMetadata
    {
        public long Created { get; set; }
        public long Expires { get; set; }
        public string Nonce { get; set; }
    }

    /// <summary>
    /// HTTP client message handler to automatically sign outgoing requests
    /// </summary>
    public class HttpSignatureClientHandler : DelegatingHandler
    {
        private readonly HttpSignatureHandler _signatureHandler;
        private readonly string _griffinApiKey;

        /// <summary>
        /// Creates a new HTTP signature client handler using Ed25519 key
        /// </summary>
        public HttpSignatureClientHandler(
            byte[] privateKeyBytes,
            string keyId,
            string griffinApiKey,
            TimeSpan signatureExpiration,
            List<string> componentsToSign = null)
        {
            _signatureHandler = new HttpSignatureHandler(
                privateKeyBytes,
                keyId,
                signatureExpiration,
                componentsToSign);

            _griffinApiKey = griffinApiKey;

            InnerHandler = new HttpClientHandler();
        }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            System.Threading.CancellationToken cancellationToken)
        {
            // Sign the request
            await _signatureHandler.SignRequest(request);

            // Debug: Print all request headers after signing
            LogRequestHeaders(request);

            return await base.SendAsync(request, cancellationToken);
        }

        private void LogRequestHeaders(HttpRequestMessage request)
        {
            Console.WriteLine("\nFinal request headers:");
            foreach (var header in request.Headers)
            {
                Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }
            if (request.Content != null)
            {
                foreach (var header in request.Content.Headers)
                {
                    Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
                }
            }
        }
    }

    /// <summary>
    /// Extension methods for HttpClient to enable HTTP signatures
    /// </summary>
    public static class HttpClientExtensions
    {
        /// <summary>
        /// Configure HttpClient to sign requests with HTTP Message Signatures using Ed25519
        /// and add Griffin API Key authorization header
        /// </summary>
        public static HttpClient UseHttpMessageSignatures(
            this HttpClient client,
            byte[] privateKeyBytes,
            string keyId,
            string griffinApiKey,
            TimeSpan signatureExpiration,
            List<string> componentsToSign = null)
        {
            var handler = new HttpSignatureClientHandler(
                privateKeyBytes,
                keyId,
                griffinApiKey,
                signatureExpiration,
                componentsToSign);

            var httpClient = new HttpClient(handler)
            {
                BaseAddress = client.BaseAddress,
                Timeout = client.Timeout,
                MaxResponseContentBufferSize = client.MaxResponseContentBufferSize
            };

            // Copy headers
            foreach (var header in client.DefaultRequestHeaders)
            {
                httpClient.DefaultRequestHeaders.TryAddWithoutValidation(header.Key, header.Value);
            }

            // Add Griffin API Key header
            httpClient.DefaultRequestHeaders.Add("Authorization", $"GriffinAPIKey {griffinApiKey}");

            return httpClient;
        }

        /// <summary>
        /// Configure HttpClient to sign requests with HTTP Message Signatures using PEM-encoded Ed25519 key
        /// </summary>
        public static HttpClient UseHttpMessageSignaturesWithPem(
            this HttpClient client,
            string pemPrivateKey,
            string keyId,
            string griffinApiKey,
            TimeSpan signatureExpiration,
            List<string> componentsToSign = null)
        {
            // Extract raw private key bytes from PEM
            byte[] privateKeyBytes = HttpSignatureHandler.ExtractPrivateKeyFromPem(pemPrivateKey);

            return client.UseHttpMessageSignatures(
                privateKeyBytes,
                keyId,
                griffinApiKey,
                signatureExpiration,
                componentsToSign);
        }
    }

    /// <summary>
    /// Sample usage of HTTP Message Signatures with Ed25519
    /// </summary>
    public class SignatureExample
    {
        public static async Task Run()
        {
            try
            {
                Console.WriteLine("Using Ed25519 key from file and API key from environment variable");
                await UseKeyFromFileAndEnvVar();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }

        private static async Task UseKeyFromFileAndEnvVar()
        {
            try
            {
                // Get credentials from environment
                var credentials = GetCredentials();
                
                // Create HTTP client with signature handler
                var httpClient = CreateSignedHttpClient(credentials);

                // Send test request to verify signature
                await SendVerificationRequest(httpClient);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in UseKeyFromFileAndEnvVar: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
        
        private static GriffinCredentials GetCredentials()
        {
            // Read PEM format Ed25519 private key from file
            string pemPrivateKey = File.ReadAllText("private_key.pem");
            Console.WriteLine("Successfully read private key from file");

            // Get Griffin API Key from environment variable
            string griffinApiKey = Environment.GetEnvironmentVariable("GRIFFIN_API_KEY");
            if (string.IsNullOrEmpty(griffinApiKey))
            {
                throw new Exception("GRIFFIN_API_KEY environment variable is not set");
            }
            Console.WriteLine("Successfully retrieved API key from environment variable");

            // Get Griffin Key ID from environment variable
            string griffinKeyId = Environment.GetEnvironmentVariable("GRIFFIN_KEY_ID");
            if (string.IsNullOrEmpty(griffinKeyId))
            {
                throw new Exception("GRIFFIN_KEY_ID environment variable is not set");
            }
            Console.WriteLine("Successfully retrieved key ID from environment variable");
            
            return new GriffinCredentials
            {
                PrivateKeyPem = pemPrivateKey,
                ApiKey = griffinApiKey,
                KeyId = griffinKeyId
            };
        }
        
        private static HttpClient CreateSignedHttpClient(GriffinCredentials credentials)
        {
            var componentsToSign = new List<string>
            {
                "@method",
                "@target-uri",
                "@authority",
                "@path",
                "content-type",
                "content-digest",
                "content-length",
                "date"
            };
            
            return new HttpClient().UseHttpMessageSignaturesWithPem(
                credentials.PrivateKeyPem,
                credentials.KeyId,
                credentials.ApiKey,
                TimeSpan.FromMinutes(5),
                componentsToSign);
        }
        
        private static async Task SendVerificationRequest(HttpClient httpClient)
        {
            // Create request body
            var requestBody = JsonSerializer.Serialize(new { hello = "world" });
            Console.WriteLine($"Request Body: {requestBody}");

            // Create the request with the correct domain
            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.griffin.com/v0/security/message-signature/verify");

            // Create content with explicit control over the encoding
            var contentBytes = Encoding.UTF8.GetBytes(requestBody);
            var content = new ByteArrayContent(contentBytes);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            content.Headers.ContentLength = contentBytes.Length;
            request.Content = content;

            // Add date header
            request.Headers.Date = DateTimeOffset.UtcNow;

            // Calculate content digest directly and add it manually
            byte[] hash = SHA512.HashData(contentBytes);
            string contentDigestValue = $"sha-512=:{Convert.ToBase64String(hash)}:";
            request.Headers.TryAddWithoutValidation("Content-Digest", contentDigestValue);

            Console.WriteLine($"Manually added Content-Digest: {contentDigestValue}");
            Console.WriteLine($"Content bytes length: {contentBytes.Length}");
            Console.WriteLine($"Content as string: {Encoding.UTF8.GetString(contentBytes)}");

            // Send signed request
            Console.WriteLine("Sending request...");
            var response = await httpClient.SendAsync(request);
            Console.WriteLine($"Response: {response.StatusCode}");

            // Read response content
            var responseContent = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"Response Content: {responseContent}");

            // Print all request headers for debugging
            Console.WriteLine("\nRequest Headers:");
            foreach (var header in httpClient.DefaultRequestHeaders)
            {
                Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }
        }
    }
    
    /// <summary>
    /// Container for Griffin API credentials
    /// </summary>
    public class GriffinCredentials
    {
        public string PrivateKeyPem { get; set; }
        public string ApiKey { get; set; }
        public string KeyId { get; set; }
    }
}