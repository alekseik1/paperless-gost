## paperless-gost

`paperless-gost` is a Paperless-ngx parser plugin for attached CMS/CAdES
documents that use GOST algorithm identifiers and encapsulate a PDF.

Paperless discovers `GOSTCMSParser` through the `paperless_ngx.parsers` entry
point. The original `.p7m` or `.sig` file remains the original document; its
embedded PDF is supplied as the PDF rendition.

### Note for humans

This plugin was fully vibe-coded by Codex using 5.6-terra (high effort) on 2026-08-24.
No warranty for broken documents. 

### Docker Compose installation

This package is not published to a package index. Build a local wheel from
this checkout and install that wheel in the Paperless container at startup.
These steps assume the standard Paperless Docker Compose service is named
`webserver`.

1. Build the wheel:

   ```bash
   uv build
   ```

2. Create `custom-cont-init.d/10-install-paperless-gost.sh` beside your
   `docker-compose.yml` with the following contents:

   ```sh
   #!/bin/sh
   set -eu

   set -- /opt/paperless-gost/paperless_gost-*.whl
   test "$#" -eq 1
   pip install --no-cache-dir --upgrade "$1"
   ```

   Make the script executable:

   ```bash
   chmod +x custom-cont-init.d/10-install-paperless-gost.sh
   ```

3. Add these read-only volumes to the `webserver` service in
   `docker-compose.yml`:

   ```yaml
   services:
     webserver:
       volumes:
         - ./dist:/opt/paperless-gost:ro
         - ./custom-cont-init.d:/custom-cont-init.d:ro
   ```

4. Recreate the webserver and confirm that Paperless discovered the parser:

   ```bash
   docker compose up -d --force-recreate webserver
   docker compose logs --tail=200 webserver | grep -F "Loaded third-party parser 'GOST CMS/CAdES PDF Parser'"
   ```

   If the log line is absent, inspect the full webserver startup log and check
   that exactly one `paperless_gost-*.whl` file is present in `dist/`.

Supported input is detected from CMS ASN.1 content and GOST OIDs, rather than
the filename. The plugin accepts attached CMS/CAdES payloads only when the
encapsulated content is a PDF. Detached `.sig`/`.p7s` signatures are
unsupported and attached non-PDF content fails with a clear parser error.

The plugin does not verify cryptographic signatures or otherwise check crypto
validity. It does not provide a GOST crypto backend, trust-chain or revocation
checks, timestamp validation, or any assertion that a signature is valid. When
present, signing time, signer subject/issuer, and GOST/signature algorithm
identifiers are exposed as unverified metadata.

## License

Licensed under the [GNU General Public License v3.0 or later](LICENSE).
