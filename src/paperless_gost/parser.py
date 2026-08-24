from __future__ import annotations

import datetime
import shutil
import tempfile
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

from asn1crypto import cms, x509
from django.conf import settings
from documents.parsers import ParseError, get_default_thumbnail
from paperless.parsers import MetadataEntry, ParserContext

if TYPE_CHECKING:
    from typing import Self


_SUPPORTED_MIME_TYPES = {
    "application/octet-stream": ".p7m",
    "application/pkcs7-mime": ".p7m",
    "application/pkcs7-signature": ".sig",
    "application/x-pkcs7-mime": ".p7m",
    "application/x-pkcs7-signature": ".sig",
}
_GOST_DIGEST_ALGORITHM_OIDS = frozenset(
    {
        "1.2.643.2.2.9",
        "1.2.643.7.1.1.2.2",
        "1.2.643.7.1.1.2.3",
    },
)
_GOST_SIGNATURE_ALGORITHM_OIDS = frozenset(
    {
        "1.2.643.2.2.20",
        "1.2.643.2.2.3",
        "1.2.643.2.2.4",
        "1.2.643.2.2.19",
        "1.2.643.7.1.1.3.2",
        "1.2.643.7.1.1.3.3",
    },
)
_METADATA_NAMESPACE = "https://github.com/alekseik1/paperless-gost"


class GOSTCMSParser:
    """Expose the PDF embedded in an attached GOST CMS/CAdES document."""

    name = "GOST CMS/CAdES PDF Parser"
    version = "0.1.0"
    author = "alekseik1"
    url = "https://github.com/alekseik1/paperless-gost"

    def __init__(self, logging_group: object = None) -> None:
        settings.SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
        self._tempdir = Path(
            tempfile.mkdtemp(prefix="paperless-gost-", dir=settings.SCRATCH_DIR),
        )
        self._archive_path: Path | None = None

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        shutil.rmtree(self._tempdir, ignore_errors=True)

    @classmethod
    def supported_mime_types(cls) -> dict[str, str]:
        return _SUPPORTED_MIME_TYPES

    @classmethod
    def score(
        cls,
        mime_type: str,
        filename: str,
        path: Path | None = None,
    ) -> int | None:
        if mime_type not in _SUPPORTED_MIME_TYPES or path is None:
            return None
        try:
            return 100 if _is_gost_signed_data(path.read_bytes()) else None
        except OSError:
            return None

    @property
    def can_produce_archive(self) -> bool:
        return False

    @property
    def requires_pdf_rendition(self) -> bool:
        return True

    def configure(self, context: ParserContext) -> None:
        pass

    def parse(
        self,
        document_path: Path,
        mime_type: str,
        *,
        produce_archive: bool = True,
    ) -> None:
        try:
            signed_data = _load_gost_signed_data(document_path.read_bytes())
        except (OSError, ValueError) as error:
            raise ParseError(f"Unable to read GOST CMS document: {error}") from error

        encapsulated_content = signed_data["encap_content_info"]["content"]
        content = encapsulated_content.native
        if content is None:
            raise ParseError(
                "Detached CMS/CAdES signatures are unsupported: no encapsulated PDF is present.",
            )
        if not isinstance(content, bytes) or not content.startswith(b"%PDF-"):
            raise ParseError("Attached CMS/CAdES content is not a PDF.")

        self._archive_path = self._tempdir / "rendition.pdf"
        self._archive_path.write_bytes(content)

    def get_text(self) -> str:
        return ""

    def get_date(self) -> datetime.datetime | None:
        return None

    def get_archive_path(self) -> Path | None:
        return self._archive_path

    def get_thumbnail(self, document_path: Path, mime_type: str) -> Path:
        thumbnail = self._tempdir / "thumbnail.webp"
        shutil.copyfile(get_default_thumbnail(), thumbnail)
        return thumbnail

    def get_page_count(self, document_path: Path, mime_type: str) -> int | None:
        return None

    def extract_metadata(
        self,
        document_path: Path,
        mime_type: str,
    ) -> list[MetadataEntry]:
        try:
            return _metadata(_load_gost_signed_data(document_path.read_bytes()))
        except (OSError, ValueError):
            return []


def _load_gost_signed_data(data: bytes) -> cms.SignedData:
    try:
        content_info = cms.ContentInfo.load(data, strict=True)
    except ValueError as error:
        raise ValueError("not a CMS ContentInfo structure") from error
    if content_info["content_type"].native != "signed_data":
        raise ValueError("CMS ContentInfo does not contain SignedData")
    signed_data = content_info["content"]
    signer_infos = signed_data["signer_infos"]
    if not signer_infos or any(
        signer_info["signature_algorithm"]["algorithm"].dotted
        not in _GOST_SIGNATURE_ALGORITHM_OIDS
        for signer_info in signer_infos
    ):
        raise ValueError("CMS SignedData does not contain a supported GOST signer")
    return signed_data


def _is_gost_signed_data(data: bytes) -> bool:
    try:
        _load_gost_signed_data(data)
    except ValueError:
        return False
    return True


def _gost_algorithm_oids(signed_data: cms.SignedData) -> list[str]:
    digest_oids = set()
    signature_oids = set()
    for signer_info in _gost_signer_infos(signed_data):
        digest_oid = signer_info["digest_algorithm"]["algorithm"].dotted
        if digest_oid in _GOST_DIGEST_ALGORITHM_OIDS:
            digest_oids.add(digest_oid)
        signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted
        signature_oids.add(signature_oid)
    return sorted(digest_oids | signature_oids)


def _gost_signer_infos(signed_data: cms.SignedData) -> list[cms.SignerInfo]:
    return [
        signer_info
        for signer_info in signed_data["signer_infos"]
        if signer_info["signature_algorithm"]["algorithm"].dotted
        in _GOST_SIGNATURE_ALGORITHM_OIDS
    ]


def _metadata(signed_data: cms.SignedData) -> list[MetadataEntry]:
    entries = [_entry("verification", "Not performed; cryptographic validity was not assessed.")]
    algorithm_oids = _gost_algorithm_oids(signed_data)
    if algorithm_oids:
        entries.append(_entry("gost_algorithm_oids", ", ".join(algorithm_oids)))

    for signer_info in signed_data["signer_infos"]:
        signing_time = _signing_time(signer_info)
        if signing_time is not None:
            entries.append(_entry("signing_time", signing_time.isoformat()))
        signature_oid = signer_info["signature_algorithm"]["algorithm"].dotted
        entries.append(_entry("signature_algorithm", signature_oid))
        certificate = _signer_certificate(signed_data, signer_info)
        if certificate is not None:
            entries.append(_entry("signer_subject", certificate.subject.human_friendly))
            entries.append(_entry("signer_issuer", certificate.issuer.human_friendly))
    return entries


def _signing_time(signer_info: cms.SignerInfo) -> datetime.datetime | None:
    signed_attributes = signer_info["signed_attrs"]
    if signed_attributes.native is None:
        return None
    for attribute in signed_attributes:
        if attribute["type"].native == "signing_time":
            values = attribute["values"].native
            if values:
                return values[0]
    return None


def _signer_certificate(
    signed_data: cms.SignedData,
    signer_info: cms.SignerInfo,
) -> x509.Certificate | None:
    signer_id = signer_info["sid"]
    if signer_id.name != "issuer_and_serial_number":
        return None
    issuer_and_serial = signer_id.chosen
    for certificate_choice in signed_data["certificates"] or []:
        if certificate_choice.name != "certificate":
            continue
        certificate = certificate_choice.chosen
        if (
            certificate.issuer.dump() == issuer_and_serial["issuer"].dump()
            and certificate.serial_number == issuer_and_serial["serial_number"].native
        ):
            return certificate
    return None


def _entry(key: str, value: str) -> MetadataEntry:
    return {
        "namespace": _METADATA_NAMESPACE,
        "prefix": "gost",
        "key": key,
        "value": value[:512],
    }
