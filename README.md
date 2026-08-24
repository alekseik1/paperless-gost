## paperless-gost

`paperless-gost` is a Paperless-ngx parser plugin for attached CMS/CAdES
documents that use GOST algorithm identifiers and encapsulate a PDF.

Install it into the same Python environment as Paperless-ngx:

```bash
pip install paperless-gost
```

Paperless discovers `GOSTCMSParser` through the `paperless_ngx.parsers` entry
point. The original `.p7m` or `.sig` file remains the original document; its
embedded PDF is supplied as the PDF rendition.

Supported input is detected from CMS ASN.1 content and GOST OIDs, rather than
the filename. The plugin accepts attached CMS/CAdES payloads only when the
encapsulated content is a PDF. Detached `.sig`/`.p7s` signatures and attached
non-PDF content fail with a clear parser error.

The plugin does not verify cryptographic signatures. It does not provide a
GOST crypto backend, trust-chain or revocation checks, timestamp validation, or
any assertion that a signature is valid. When present, signing time, signer
subject/issuer, and GOST/signature algorithm identifiers are exposed as
unverified metadata.
