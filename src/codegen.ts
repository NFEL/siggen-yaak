// Generates standalone, runnable source code snippets that reproduce the PAYOK
// RSA-SHA256 signature algorithm implemented in index.ts, for several languages.
//
// Algorithm (must stay in sync with generateSignature() in index.ts):
//   message   = <body> + "&" + <path>
//   signature = Base64( RSA-SHA256-sign(privateKey, message) )
//
// The private key is expected to be a PKCS#8 RSA private key, either as raw
// Base64 (no PEM headers) or a full "-----BEGIN PRIVATE KEY-----" PEM block.
//
// Each snippet also includes a verifySignature() counterpart that verifies a
// signature against an RSA public key (X.509 / SubjectPublicKeyInfo, Base64 or
// PEM), for verifying an incoming PAYOK notification/webhook. It signs over
// <body> alone (empty path) - confirmed against a real PAYOK notification
// payload to be signed over the body only, with no path involved.

export type SupportedLanguage =
  | "javascript"
  | "python"
  | "java"
  | "go"
  | "php"
  | "rust"
  | "csharp";

export const LANGUAGE_OPTIONS: Array<{
  label: string;
  value: SupportedLanguage;
}> = [
    { label: "JavaScript (Node.js)", value: "javascript" },
    { label: "Python", value: "python" },
    { label: "Java", value: "java" },
    { label: "Go", value: "go" },
    { label: "PHP", value: "php" },
    { label: "Rust", value: "rust" },
    { label: "C# (.NET)", value: "csharp" },
  ];

const PRIVATE_KEY_PLACEHOLDER = "PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE";
const WEBHOOK_BODY_PLACEHOLDER = "PASTE_RECEIVED_WEBHOOK_BODY_HERE";
const WEBHOOK_SIGNATURE_PLACEHOLDER = "PASTE_RECEIVED_SIGNATURE_HERE";
const WEBHOOK_PUBLIC_KEY_PLACEHOLDER = "PASTE_PAYOK_BASE64_PUBLIC_KEY_HERE";

/** Escapes a raw string value for embedding inside a double-quoted string literal. */
function escapeString(value: string, lang: SupportedLanguage): string {
  let escaped = value
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n")
    .replace(/\t/g, "\\t");
  // PHP double-quoted strings interpolate "$var" — escape literal dollar signs.
  if (lang === "php") {
    escaped = escaped.replace(/\$/g, "\\$");
  }
  return escaped;
}

export interface CodegenInput {
  path: string;
  body: string;
  /** Selected JSON is signed as-is, without the PAYOK endpoint suffix. */
  messageMode?: "payok" | "selected";
  compactJws?: boolean;
  /** The actual private key resolved from the request's `sign` header, if found. */
  privateKey?: string;
}

export function generateCode(
  lang: SupportedLanguage,
  input: CodegenInput,
): string {
  if (lang === "rust") return generateRust(input);
  if (input.compactJws) {
    const signingInput = `${Buffer.from('{"alg":"RS256","typ":"JWS"}').toString("base64url")}.${Buffer.from(input.body).toString("base64url")}`;
    const code = generateCode(lang, { ...input, body: signingInput, messageMode: "selected", compactJws: false });
    // Keep the language-specific signing helpers unchanged: they sign the JWS input bytes.
    switch (lang) {
      case "javascript": return code.replace("console.log('sign:', signature);", "console.log('sign:', BODY + '.' + Buffer.from(signature, 'base64').toString('base64url'));");
      case "python": return code.replace('print("sign:", signature)', 'print("sign:", BODY + "." + base64.urlsafe_b64encode(base64.b64decode(signature)).decode("ascii").rstrip("="))');
      case "java": return code.replace('System.out.println("sign: " + sign);', 'System.out.println("sign: " + body + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getDecoder().decode(sign)));');
      case "go": return code.replace('fmt.Println("sign:", signature)', 'fmt.Println("sign:", body + "." + strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(signature), "="))');
      case "php": return code.replace('$signature = generateSignature($body, $path, $privateKeyBase64);', '$signature = $body . "." . rtrim(strtr(generateSignature($body, $path, $privateKeyBase64), "+/", "-_"), "=");');
      case "csharp": return code.replace('Console.WriteLine($"sign: {signature}");', 'Console.WriteLine("sign: " + body + "." + signature.TrimEnd(\'=\').Replace(\'+\', \'-\').Replace(\'/\', \'_\'));');
    }
  }
  const selected = input.messageMode === "selected";
  const path = selected ? "" : input.path || "/api-pay/payment/V3.2/order/create-api";
  const body = input.body;
  const privateKey = input.privateKey || PRIVATE_KEY_PLACEHOLDER;

  switch (lang) {
    case "javascript":
      return generateJavaScript(path, body, privateKey, selected);
    case "python":
      return generatePython(path, body, privateKey, selected);
    case "java":
      return generateJava(path, body, privateKey, selected);
    case "go":
      return generateGo(path, body, privateKey, selected);
    case "php":
      return generatePhp(path, body, privateKey, selected);
    case "csharp":
      return generateCSharp(path, body, privateKey, selected);
    default:
      return "";
  }
}

/**
 * Banner prepended to the generated code:
 * - If a real private key was resolved from the request, warn that it's a real secret.
 * - Otherwise, tell the user exactly what to do to fill it in manually.
 */
function secretWarning(privateKey: string, commentPrefix: string): string {
  if (privateKey === PRIVATE_KEY_PLACEHOLDER) {
    return (
      `${commentPrefix} TODO: no private_key was found on this request's "sign" header ` +
      `(payok.signature(...) tag).\n` +
      `${commentPrefix} Replace PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE below with your ` +
      `own PKCS#8 Base64 private key before running this code.\n`
    );
  }
  return `${commentPrefix} WARNING: this file embeds your REAL private key. Do not commit or share it.\n`;
}

function generateJavaScript(
  path: string,
  body: string,
  privateKey: string,
  selected: boolean,
): string {
  const p = escapeString(path, "javascript");
  const b = escapeString(body, "javascript");
  const k = escapeString(privateKey, "javascript");
  return `${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — Node.js (built-in "crypto" module)
const crypto = require('crypto');

function buildPrivateKeyPem(base64Key) {
  const stripped = base64Key
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, '')
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, '')
    .replace(/\\s+/g, '');
  return \`-----BEGIN PRIVATE KEY-----\\n\${stripped}\\n-----END PRIVATE KEY-----\`;
}

function generateSignature(body, path, privateKeyBase64) {
  const message = ${selected ? "body" : "`\${body}&\${path}`"};
  const pem = buildPrivateKeyPem(privateKeyBase64);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(message, 'utf8');
  return sign.sign(pem, 'base64');
}

function buildPublicKeyPem(base64Key) {
  const stripped = base64Key
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\\s+/g, '');
  return \`-----BEGIN PUBLIC KEY-----\\n\${stripped}\\n-----END PUBLIC KEY-----\`;
}

// Verifies a signature against a public key. If path is empty, the message is
// just body (no separator) — this matches how PAYOK signs incoming
// notifications/webhooks, which have no "path" of their own.
function verifySignature(body, path, signatureBase64, publicKeyBase64) {
  const message = path ? \`\${body}&\${path}\` : body;
  const pem = buildPublicKeyPem(publicKeyBase64);
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(message, 'utf8');
  return verify.verify(pem, signatureBase64, 'base64');
}

// --- Values captured from the current request ---
const PRIVATE_KEY_BASE64 = "${k}";
const PATH = "${p}";
const BODY = "${b}";

const signature = generateSignature(BODY, PATH, PRIVATE_KEY_BASE64);
console.log('sign:', signature);

// --- Verify an incoming PAYOK notification/webhook ---
// PAYOK signs notifications/webhooks over the BODY ONLY (empty path). Paste
// the body, signature, and PAYOK's public key you actually received below.
const WEBHOOK_BODY = "${WEBHOOK_BODY_PLACEHOLDER}";
const WEBHOOK_SIGNATURE = "${WEBHOOK_SIGNATURE_PLACEHOLDER}";
const WEBHOOK_PUBLIC_KEY_BASE64 = "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}";
const isWebhookValid = verifySignature(WEBHOOK_BODY, '', WEBHOOK_SIGNATURE, WEBHOOK_PUBLIC_KEY_BASE64);
console.log('webhook valid:', isWebhookValid);
`;
}

function generatePython(
  path: string,
  body: string,
  privateKey: string,
  selected: boolean,
): string {
  const p = escapeString(path, "python");
  const b = escapeString(body, "python");
  const k = escapeString(privateKey, "python");
  return `${secretWarning(privateKey, "#")}# PAYOK RSA-SHA256 signature — Python
# Requires: pip install cryptography
import base64
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def build_private_key_pem(base64_key: str) -> bytes:
    stripped = (
        base64_key.replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
    )
    stripped = "".join(stripped.split())
    pem = "-----BEGIN PRIVATE KEY-----\\n" + stripped + "\\n-----END PRIVATE KEY-----"
    return pem.encode("utf-8")


def generate_signature(body: str, path: str, private_key_base64: str) -> str:
    message = ${selected ? "body" : 'f"{body}&{path}"'}.encode("utf-8")
    pem = build_private_key_pem(private_key_base64)
    private_key = serialization.load_pem_private_key(pem, password=None)
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("utf-8")


def build_public_key_pem(base64_key: str) -> bytes:
    stripped = base64_key.replace("-----BEGIN PUBLIC KEY-----", "").replace(
        "-----END PUBLIC KEY-----", ""
    )
    stripped = "".join(stripped.split())
    pem = "-----BEGIN PUBLIC KEY-----\\n" + stripped + "\\n-----END PUBLIC KEY-----"
    return pem.encode("utf-8")


def verify_signature(
    body: str, path: str, signature_base64: str, public_key_base64: str
) -> bool:
    """Verifies a signature against a public key.

    If path is empty, the message is just body (no separator) — this matches
    how PAYOK signs incoming notifications/webhooks, which have no "path" of
    their own.
    """
    message = (f"{body}&{path}" if path else body).encode("utf-8")
    pem = build_public_key_pem(public_key_base64)
    public_key = serialization.load_pem_public_key(pem)
    signature = base64.b64decode(signature_base64)
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# --- Values captured from the current request ---
PRIVATE_KEY_BASE64 = "${k}"
PATH = "${p}"
BODY = "${b}"

if __name__ == "__main__":
    signature = generate_signature(BODY, PATH, PRIVATE_KEY_BASE64)
    print("sign:", signature)

    # --- Verify an incoming PAYOK notification/webhook ---
    # PAYOK signs notifications/webhooks over the BODY ONLY (empty path). Paste
    # the body, signature, and PAYOK's public key you actually received below.
    WEBHOOK_BODY = "${WEBHOOK_BODY_PLACEHOLDER}"
    WEBHOOK_SIGNATURE = "${WEBHOOK_SIGNATURE_PLACEHOLDER}"
    WEBHOOK_PUBLIC_KEY_BASE64 = "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}"
    is_webhook_valid = verify_signature(
        WEBHOOK_BODY, "", WEBHOOK_SIGNATURE, WEBHOOK_PUBLIC_KEY_BASE64
    )
    print("webhook valid:", is_webhook_valid)
`;
}

function generateJava(path: string, body: string, privateKey: string, selected: boolean): string {
  const p = escapeString(path, "java");
  const b = escapeString(body, "java");
  const k = escapeString(privateKey, "java");
  return `${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — Java (JDK standard library only)
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PayokSignature {

    public static String buildBase64Key(String rawKey) {
        return rawKey
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\\\s+", "");
    }

    public static String generateSignature(String body, String path, String privateKeyBase64) throws Exception {
        String message = ${selected ? "body" : 'body + "&" + path'};
        String cleanedKey = buildBase64Key(privateKeyBase64);
        byte[] keyBytes = Base64.getDecoder().decode(cleanedKey);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes(StandardCharsets.UTF_8));

        return Base64.getEncoder().encodeToString(signature.sign());
    }

    public static String buildBase64PublicKey(String rawKey) {
        return rawKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\\\s+", "");
    }

    /**
     * Verifies a signature against a public key. If path is empty, the message
     * is just body (no separator) — this matches how PAYOK signs incoming
     * notifications/webhooks, which have no "path" of their own.
     */
    public static boolean verifySignature(String body, String path, String signatureBase64, String publicKeyBase64) throws Exception {
        String message = (path == null || path.isEmpty()) ? body : body + "&" + path;
        String cleanedKey = buildBase64PublicKey(publicKeyBase64);
        byte[] keyBytes = Base64.getDecoder().decode(cleanedKey);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));

        return verifier.verify(Base64.getDecoder().decode(signatureBase64));
    }

    public static void main(String[] args) throws Exception {
        // --- Values captured from the current request ---
        String privateKeyBase64 = "${k}";
        String path = "${p}";
        String body = "${b}";

        String sign = generateSignature(body, path, privateKeyBase64);
        System.out.println("sign: " + sign);

        // --- Verify an incoming PAYOK notification/webhook ---
        // PAYOK signs notifications/webhooks over the BODY ONLY (empty path).
        // Paste the body, signature, and PAYOK's public key you actually
        // received below.
        String webhookBody = "${WEBHOOK_BODY_PLACEHOLDER}";
        String webhookSignature = "${WEBHOOK_SIGNATURE_PLACEHOLDER}";
        String webhookPublicKeyBase64 = "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}";
        boolean isWebhookValid = verifySignature(webhookBody, "", webhookSignature, webhookPublicKeyBase64);
        System.out.println("webhook valid: " + isWebhookValid);
    }
}
`;
}

function generateGo(path: string, body: string, privateKey: string, selected: boolean): string {
  const p = escapeString(path, "go");
  const b = escapeString(body, "go");
  const k = escapeString(privateKey, "go");
  return `${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — Go (standard library only)
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

var pemHeaderRe = regexp.MustCompile(\`-----(BEGIN|END) (RSA )?PRIVATE KEY-----\`)
var pemPublicKeyHeaderRe = regexp.MustCompile(\`-----(BEGIN|END) PUBLIC KEY-----\`)

func cleanBase64Key(raw string) string {
	stripped := pemHeaderRe.ReplaceAllString(raw, "")
	return strings.Join(strings.Fields(stripped), "")
}

func cleanBase64PublicKey(raw string) string {
	stripped := pemPublicKeyHeaderRe.ReplaceAllString(raw, "")
	return strings.Join(strings.Fields(stripped), "")
}

func generateSignature(body, path, privateKeyBase64 string) (string, error) {
	message := ${selected ? "body" : 'body + "&" + path'}

	keyBytes, err := base64.StdEncoding.DecodeString(cleanBase64Key(privateKeyBase64))
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	keyInterface, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("parse pkcs8 private key: %w", err)
	}

	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("not an RSA private key")
	}

	hashed := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign message: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// verifySignature verifies a signature against a public key. If path is
// empty, the message is just body (no separator) - this matches how PAYOK
// signs incoming notifications/webhooks, which have no "path" of their own.
func verifySignature(body, path, signatureBase64, publicKeyBase64 string) (bool, error) {
	message := body
	if path != "" {
		message = body + "&" + path
	}

	keyBytes, err := base64.StdEncoding.DecodeString(cleanBase64PublicKey(publicKeyBase64))
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}

	keyInterface, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return false, fmt.Errorf("parse pkix public key: %w", err)
	}

	publicKey, ok := keyInterface.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("not an RSA public key")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}

	hashed := sha256.Sum256([]byte(message))
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signatureBytes)
	return err == nil, nil
}

func main() {
	// --- Values captured from the current request ---
	privateKeyBase64 := "${k}"
	path := "${p}"
	body := "${b}"

	signature, err := generateSignature(body, path, privateKeyBase64)
	if err != nil {
		panic(err)
	}
	fmt.Println("sign:", signature)

	// --- Verify an incoming PAYOK notification/webhook ---
	// PAYOK signs notifications/webhooks over the BODY ONLY (empty path).
	// Paste the body, signature, and PAYOK's public key you actually received
	// below.
	webhookBody := "${WEBHOOK_BODY_PLACEHOLDER}"
	webhookSignature := "${WEBHOOK_SIGNATURE_PLACEHOLDER}"
	webhookPublicKeyBase64 := "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}"
	isWebhookValid, err := verifySignature(webhookBody, "", webhookSignature, webhookPublicKeyBase64)
	if err != nil {
		panic(err)
	}
	fmt.Println("webhook valid:", isWebhookValid)
}
`;
}

function generatePhp(path: string, body: string, privateKey: string, selected: boolean): string {
  const p = escapeString(path, "php");
  const b = escapeString(body, "php");
  const k = escapeString(privateKey, "php");
  return `<?php
${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — PHP (requires the "openssl" extension)

function buildPrivateKeyPem(string $base64Key): string
{
    $stripped = preg_replace('/-----(BEGIN|END) (RSA )?PRIVATE KEY-----/', '', $base64Key);
    $stripped = preg_replace('/\\s+/', '', $stripped);
    return "-----BEGIN PRIVATE KEY-----\\n" . chunk_split($stripped, 64, "\\n") . "-----END PRIVATE KEY-----\\n";
}

function generateSignature(string $body, string $path, string $privateKeyBase64): string
{
    $message = ${selected ? "$body" : "$body . '&' . $path"};
    $pem = buildPrivateKeyPem($privateKeyBase64);

    $privateKey = openssl_pkey_get_private($pem);
    if ($privateKey === false) {
        throw new RuntimeException('Invalid private key: ' . openssl_error_string());
    }

    openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA256);

    return base64_encode($signature);
}

function buildPublicKeyPem(string $base64Key): string
{
    $stripped = preg_replace('/-----(BEGIN|END) PUBLIC KEY-----/', '', $base64Key);
    $stripped = preg_replace('/\\s+/', '', $stripped);
    return "-----BEGIN PUBLIC KEY-----\\n" . chunk_split($stripped, 64, "\\n") . "-----END PUBLIC KEY-----\\n";
}

// Verifies a signature against a public key. If $path is empty, the message
// is just $body (no separator) - this matches how PAYOK signs incoming
// notifications/webhooks, which have no "path" of their own.
function verifySignature(string $body, string $path, string $signatureBase64, string $publicKeyBase64): bool
{
    $message = $path !== '' ? $body . '&' . $path : $body;
    $pem = buildPublicKeyPem($publicKeyBase64);

    $publicKey = openssl_pkey_get_public($pem);
    if ($publicKey === false) {
        throw new RuntimeException('Invalid public key: ' . openssl_error_string());
    }

    $signature = base64_decode($signatureBase64);
    $result = openssl_verify($message, $signature, $publicKey, OPENSSL_ALGO_SHA256);

    return $result === 1;
}

// --- Values captured from the current request ---
$privateKeyBase64 = "${k}";
$path = "${p}";
$body = "${b}";

$signature = generateSignature($body, $path, $privateKeyBase64);
echo "sign: {$signature}\\n";

// --- Verify an incoming PAYOK notification/webhook ---
// PAYOK signs notifications/webhooks over the BODY ONLY (empty path). Paste
// the body, signature, and PAYOK's public key you actually received below.
$webhookBody = "${WEBHOOK_BODY_PLACEHOLDER}";
$webhookSignature = "${WEBHOOK_SIGNATURE_PLACEHOLDER}";
$webhookPublicKeyBase64 = "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}";
$isWebhookValid = verifySignature($webhookBody, '', $webhookSignature, $webhookPublicKeyBase64);
echo "webhook valid: " . ($isWebhookValid ? 'true' : 'false') . "\\n";
`;
}

function generateCSharp(
  path: string,
  body: string,
  privateKey: string,
  selected: boolean,
): string {
  const p = escapeString(path, "csharp");
  const b = escapeString(body, "csharp");
  const k = escapeString(privateKey, "csharp");
  return `${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — C# (.NET 5+)
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

public static class PayokSignature
{
    public static string BuildBase64Key(string rawKey)
    {
        var stripped = Regex.Replace(rawKey, @"-----(BEGIN|END) (RSA )?PRIVATE KEY-----", "");
        stripped = Regex.Replace(stripped, @"\\s+", "");
        return stripped;
    }

    public static string GenerateSignature(string body, string path, string privateKeyBase64)
    {
        string message = ${selected ? "body" : '$"{body}&{path}"'};
        byte[] keyBytes = Convert.FromBase64String(BuildBase64Key(privateKeyBase64));

        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(keyBytes, out _);

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return Convert.ToBase64String(signature);
    }

    public static string BuildBase64PublicKey(string rawKey)
    {
        var stripped = Regex.Replace(rawKey, @"-----(BEGIN|END) PUBLIC KEY-----", "");
        stripped = Regex.Replace(stripped, @"\\s+", "");
        return stripped;
    }

    /// <summary>
    /// Verifies a signature against a public key. If path is empty, the
    /// message is just body (no separator) - this matches how PAYOK signs
    /// incoming notifications/webhooks, which have no "path" of their own.
    /// </summary>
    public static bool VerifySignature(string body, string path, string signatureBase64, string publicKeyBase64)
    {
        string message = string.IsNullOrEmpty(path) ? body : $"{body}&{path}";
        byte[] keyBytes = Convert.FromBase64String(BuildBase64PublicKey(publicKeyBase64));

        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(keyBytes, out _);

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signature = Convert.FromBase64String(signatureBase64);

        return rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    public static void Main()
    {
        // --- Values captured from the current request ---
        string privateKeyBase64 = "${k}";
        string path = "${p}";
        string body = "${b}";

        string signature = GenerateSignature(body, path, privateKeyBase64);
        Console.WriteLine($"sign: {signature}");

        // --- Verify an incoming PAYOK notification/webhook ---
        // PAYOK signs notifications/webhooks over the BODY ONLY (empty path).
        // Paste the body, signature, and PAYOK's public key you actually
        // received below.
        string webhookBody = "${WEBHOOK_BODY_PLACEHOLDER}";
        string webhookSignature = "${WEBHOOK_SIGNATURE_PLACEHOLDER}";
        string webhookPublicKeyBase64 = "${WEBHOOK_PUBLIC_KEY_PLACEHOLDER}";
        bool isWebhookValid = VerifySignature(webhookBody, "", webhookSignature, webhookPublicKeyBase64);
        Console.WriteLine($"webhook valid: {isWebhookValid}");
    }
}
`;
}

function generateRust(input: CodegenInput): string {
  const key = escapeString(input.privateKey || PRIVATE_KEY_PLACEHOLDER, "rust");
  const body = escapeString(input.body, "rust");
  const path = escapeString(input.path, "rust");
  return `${secretWarning(input.privateKey || PRIVATE_KEY_PLACEHOLDER, "//")}// Save as src/main.rs in a Cargo project.
// Add dependencies: cargo add openssl base64
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use openssl::{hash::MessageDigest, pkey::{PKey, Private, Public}, rsa::Padding, sign::{Signer, Verifier}};
use std::error::Error;

fn private_key(raw: &str) -> Result<PKey<Private>, Box<dyn Error>> {
    if raw.contains("-----BEGIN") {
        Ok(PKey::private_key_from_pem(raw.as_bytes())?)
    } else {
        let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        Ok(PKey::private_key_from_der(&STANDARD.decode(clean)?)?)
    }
}

fn public_key(raw: &str) -> Result<PKey<Public>, Box<dyn Error>> {
    if raw.contains("-----BEGIN") {
        Ok(PKey::public_key_from_pem(raw.as_bytes())?)
    } else {
        let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        Ok(PKey::public_key_from_der(&STANDARD.decode(clean)?)?)
    }
}

fn sign_message(message: &[u8], raw_key: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = private_key(raw_key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.set_rsa_padding(Padding::PKCS1)?;
    signer.update(message)?;
    Ok(signer.sign_to_vec()?)
}

fn verify_message(message: &[u8], signature: &[u8], raw_key: &str) -> Result<bool, Box<dyn Error>> {
    let key = public_key(raw_key)?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &key)?;
    verifier.set_rsa_padding(Padding::PKCS1)?;
    verifier.update(message)?;
    Ok(verifier.verify(signature)?)
}

fn verify_signature(body: &str, path: &str, signature: &str, key: &str) -> Result<bool, Box<dyn Error>> {
    let message = if path.is_empty() { body.to_owned() } else { format!("{}&{}", body, path) };
    verify_message(message.as_bytes(), &STANDARD.decode(signature)?, key)
}

fn verify_jws(token: &str, key: &str) -> Result<bool, Box<dyn Error>> {
    let parts: Vec<&str> = token.split('.').collect();
    // Require the same RS256 protected header emitted by this exporter.
    if parts.len() != 3 || URL_SAFE_NO_PAD.decode(parts[0])? != br#"{"alg":"RS256","typ":"JWS"}"# {
        return Err("Unsupported JWS protected header or invalid compact format".into());
    }
    let message = format!("{}.{}", parts[0], parts[1]);
    verify_message(message.as_bytes(), &URL_SAFE_NO_PAD.decode(parts[2])?, key)
}

fn main() -> Result<(), Box<dyn Error>> {
    let key = "${key}";
    let body = "${body}";
    let path = "${path}";
    ${input.compactJws
      ? 'let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWS"}"#);\n    let message = format!("{}.{}", header, URL_SAFE_NO_PAD.encode(body.as_bytes()));\n    let signature = sign_message(message.as_bytes(), key)?;\n    println!("sign: {}.{}", message, URL_SAFE_NO_PAD.encode(signature));'
      : `let message = ${input.messageMode === "selected" ? "body.to_owned()" : 'format!("{}&{}", body, path)'};\n    println!("sign: {}", STANDARD.encode(sign_message(message.as_bytes(), key)?));`}
    // Optional webhook: verify_signature(received_body, "", received_signature, public_key)?
    // Optional compact JWS: verify_jws(received_token, public_key)?
    Ok(())
}
`;
}
