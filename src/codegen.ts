// Generates standalone, runnable source code snippets that reproduce the PAYOK
// RSA-SHA256 signature algorithm implemented in index.ts, for several languages.
//
// Algorithm (must stay in sync with generateSignature() in index.ts):
//   message   = <body> + "&" + <path>
//   signature = Base64( RSA-SHA256-sign(privateKey, message) )
//
// The private key is expected to be a PKCS#8 RSA private key, either as raw
// Base64 (no PEM headers) or a full "-----BEGIN PRIVATE KEY-----" PEM block.

export type SupportedLanguage =
  | "javascript"
  | "python"
  | "java"
  | "go"
  | "php"
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
  { label: "C# (.NET)", value: "csharp" },
];

const PRIVATE_KEY_PLACEHOLDER = "PASTE_YOUR_BASE64_PKCS8_PRIVATE_KEY_HERE";

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
  /** The actual private key resolved from the request's `sign` header, if found. */
  privateKey?: string;
}

export function generateCode(
  lang: SupportedLanguage,
  input: CodegenInput,
): string {
  const path = input.path || "/api-pay/payment/V3.2/order/create-api";
  const body = input.body || '{"merchantOrderId":"ORDER-123","amount":10000}';
  const privateKey = input.privateKey || PRIVATE_KEY_PLACEHOLDER;

  switch (lang) {
    case "javascript":
      return generateJavaScript(path, body, privateKey);
    case "python":
      return generatePython(path, body, privateKey);
    case "java":
      return generateJava(path, body, privateKey);
    case "go":
      return generateGo(path, body, privateKey);
    case "php":
      return generatePhp(path, body, privateKey);
    case "csharp":
      return generateCSharp(path, body, privateKey);
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
  const message = \`\${body}&\${path}\`;
  const pem = buildPrivateKeyPem(privateKeyBase64);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(message, 'utf8');
  return sign.sign(pem, 'base64');
}

// --- Values captured from the current request ---
const PRIVATE_KEY_BASE64 = "${k}";
const PATH = "${p}";
const BODY = "${b}";

const signature = generateSignature(BODY, PATH, PRIVATE_KEY_BASE64);
console.log('sign:', signature);
`;
}

function generatePython(
  path: string,
  body: string,
  privateKey: string,
): string {
  const p = escapeString(path, "python");
  const b = escapeString(body, "python");
  const k = escapeString(privateKey, "python");
  return `${secretWarning(privateKey, "#")}# PAYOK RSA-SHA256 signature — Python
# Requires: pip install cryptography
import base64
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
    message = f"{body}&{path}".encode("utf-8")
    pem = build_private_key_pem(private_key_base64)
    private_key = serialization.load_pem_private_key(pem, password=None)
    signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode("utf-8")


# --- Values captured from the current request ---
PRIVATE_KEY_BASE64 = "${k}"
PATH = "${p}"
BODY = "${b}"

if __name__ == "__main__":
    signature = generate_signature(BODY, PATH, PRIVATE_KEY_BASE64)
    print("sign:", signature)
`;
}

function generateJava(path: string, body: string, privateKey: string): string {
  const p = escapeString(path, "java");
  const b = escapeString(body, "java");
  const k = escapeString(privateKey, "java");
  return `${secretWarning(privateKey, "//")}// PAYOK RSA-SHA256 signature — Java (JDK standard library only)
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
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
        String message = body + "&" + path;
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

    public static void main(String[] args) throws Exception {
        // --- Values captured from the current request ---
        String privateKeyBase64 = "${k}";
        String path = "${p}";
        String body = "${b}";

        String sign = generateSignature(body, path, privateKeyBase64);
        System.out.println("sign: " + sign);
    }
}
`;
}

function generateGo(path: string, body: string, privateKey: string): string {
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

func cleanBase64Key(raw string) string {
	stripped := pemHeaderRe.ReplaceAllString(raw, "")
	return strings.Join(strings.Fields(stripped), "")
}

func generateSignature(body, path, privateKeyBase64 string) (string, error) {
	message := body + "&" + path

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
}
`;
}

function generatePhp(path: string, body: string, privateKey: string): string {
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
    $message = $body . '&' . $path;
    $pem = buildPrivateKeyPem($privateKeyBase64);

    $privateKey = openssl_pkey_get_private($pem);
    if ($privateKey === false) {
        throw new RuntimeException('Invalid private key: ' . openssl_error_string());
    }

    openssl_sign($message, $signature, $privateKey, OPENSSL_ALGO_SHA256);

    return base64_encode($signature);
}

// --- Values captured from the current request ---
$privateKeyBase64 = "${k}";
$path = "${p}";
$body = "${b}";

$signature = generateSignature($body, $path, $privateKeyBase64);
echo "sign: {$signature}\\n";
`;
}

function generateCSharp(
  path: string,
  body: string,
  privateKey: string,
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
        string message = $"{body}&{path}";
        byte[] keyBytes = Convert.FromBase64String(BuildBase64Key(privateKeyBase64));

        using var rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(keyBytes, out _);

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signature = rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return Convert.ToBase64String(signature);
    }

    public static void Main()
    {
        // --- Values captured from the current request ---
        string privateKeyBase64 = "${k}";
        string path = "${p}";
        string body = "${b}";

        string signature = GenerateSignature(body, path, privateKeyBase64);
        Console.WriteLine($"sign: {signature}");
    }
}
`;
}
