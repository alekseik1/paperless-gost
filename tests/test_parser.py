from __future__ import annotations

import datetime
from importlib.metadata import entry_points
from pathlib import Path

import pytest
from asn1crypto import algos, cms, keys, x509
from documents.parsers import ParseError
from paperless.parsers import ParserContext, ParserProtocol

from paperless_gost.parser import GOSTCMSParser, _entry


def test_entry_point_is_discoverable() -> None:
    parser_entry_points = entry_points(group="paperless_ngx.parsers")

    assert any(
        entry_point.value == "paperless_gost.parser:GOSTCMSParser"
        for entry_point in parser_entry_points
    )


def test_attached_gost_cms_pdf_scores_parses_and_extracts_metadata(
    tmp_path: Path,
) -> None:
    source = tmp_path / "invoice.p7m"
    pdf = b"%PDF-1.7\nsynthetic document\n%%EOF\n"
    source.write_bytes(_cms(pdf))

    assert GOSTCMSParser.score("application/octet-stream", source.name, source) == 100
    with GOSTCMSParser() as parser:
        assert isinstance(parser, ParserProtocol)
        parser.configure(ParserContext())
        parser.parse(source, "application/octet-stream")

        archive = parser.get_archive_path()
        assert archive is not None
        assert archive.read_bytes() == pdf
        assert source.read_bytes() == _cms(pdf)
        metadata = parser.extract_metadata(source, "application/octet-stream")

    assert metadata == [
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "verification",
            "value": "Not performed; cryptographic validity was not assessed.",
        },
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "gost_algorithm_oids",
            "value": "1.2.643.7.1.1.2.2, 1.2.643.7.1.1.3.2",
        },
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "signing_time",
            "value": "2024-01-02T03:04:05+00:00",
        },
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "signature_algorithm",
            "value": "1.2.643.7.1.1.3.2",
        },
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "signer_subject",
            "value": "Common Name: Synthetic Signer",
        },
        {
            "namespace": "https://github.com/alekseik1/paperless-gost",
            "prefix": "gost",
            "key": "signer_issuer",
            "value": "Common Name: Synthetic Issuer",
        },
    ]


def test_arbitrary_binary_and_unsigned_pdf_are_not_claimed(tmp_path: Path) -> None:
    binary = tmp_path / "not-a-signature.sig"
    binary.write_bytes(b"not CMS")
    pdf = tmp_path / "unsigned.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%%EOF\n")

    assert GOSTCMSParser.score("application/octet-stream", binary.name, binary) is None
    assert GOSTCMSParser.score("application/pdf", pdf.name, pdf) is None


def test_non_gost_russian_algorithm_oids_are_not_claimed(tmp_path: Path) -> None:
    source = tmp_path / "not-gost.p7m"
    source.write_bytes(
        _cms(
            b"%PDF-1.7\n%%EOF\n",
            digest_oid="1.2.643.999.1",
            signature_oid="1.2.643.999.2",
        ),
    )

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) is None


@pytest.mark.parametrize(
    "digest_oid",
    [
        "1.2.643.2.2.9",
        "1.2.643.7.1.1.2.2",
        "1.2.643.7.1.1.2.3",
    ],
)
def test_every_supported_gost_digest_oid_is_accepted(
    tmp_path: Path,
    digest_oid: str,
) -> None:
    source = tmp_path / "digest.p7m"
    source.write_bytes(_cms(b"%PDF-1.7\n%%EOF\n", digest_oid=digest_oid))

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) == 100
    with GOSTCMSParser() as parser:
        metadata = parser.extract_metadata(source, "application/pkcs7-mime")
    assert next(
        entry["value"] for entry in metadata if entry["key"] == "gost_algorithm_oids"
    ) == ", ".join(sorted([digest_oid, "1.2.643.7.1.1.3.2"]))


@pytest.mark.parametrize(
    "signature_oid",
    [
        "1.2.643.2.2.20",
        "1.2.643.2.2.3",
        "1.2.643.2.2.4",
        "1.2.643.2.2.19",
        "1.2.643.7.1.1.3.2",
        "1.2.643.7.1.1.3.3",
    ],
)
def test_every_supported_gost_signature_oid_is_accepted(
    tmp_path: Path,
    signature_oid: str,
) -> None:
    source = tmp_path / "signature.p7m"
    source.write_bytes(_cms(b"%PDF-1.7\n%%EOF\n", signature_oid=signature_oid))

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) == 100


def test_gost_digest_without_a_gost_signer_is_not_claimed(tmp_path: Path) -> None:
    source = tmp_path / "unsigned-gost-digest.p7m"
    source.write_bytes(_cms(b"%PDF-1.7\n%%EOF\n", signer_infos=[]))

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) is None


def test_rsa_signer_with_a_gost_signed_data_digest_is_not_claimed(
    tmp_path: Path,
) -> None:
    source = tmp_path / "rsa-signer.p7m"
    source.write_bytes(
        _cms(
            b"%PDF-1.7\n%%EOF\n",
            signature_oid="1.2.840.113549.1.1.11",
        ),
    )

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) is None


def test_mixed_gost_and_rsa_signers_are_not_claimed(tmp_path: Path) -> None:
    source = tmp_path / "mixed-signers.p7m"
    source.write_bytes(
        _cms(
            b"%PDF-1.7\n%%EOF\n",
            signer_infos=[
                _signer_info(),
                _signer_info(signature_oid="1.2.840.113549.1.1.11"),
            ],
        ),
    )

    assert GOSTCMSParser.score("application/pkcs7-mime", source.name, source) is None


def test_empty_signing_time_values_are_ignored(tmp_path: Path) -> None:
    source = tmp_path / "empty-signing-time.p7m"
    signer_info = _signer_info()
    signer_info["signed_attrs"] = [{"type": "signing_time", "values": []}]
    source.write_bytes(_cms(b"%PDF-1.7\n%%EOF\n", signer_infos=[signer_info]))

    with GOSTCMSParser() as parser:
        metadata = parser.extract_metadata(source, "application/pkcs7-mime")

    assert "signing_time" not in {entry["key"] for entry in metadata}


def test_detached_cms_fails_explicitly(tmp_path: Path) -> None:
    source = tmp_path / "detached.sig"
    source.write_bytes(_cms(None))

    with GOSTCMSParser() as parser, pytest.raises(ParseError, match="Detached CMS/CAdES"):
        parser.parse(source, "application/pkcs7-signature")


def test_attached_non_pdf_fails_explicitly(tmp_path: Path) -> None:
    source = tmp_path / "payload.p7m"
    source.write_bytes(_cms(b"synthetic plain text"))

    with GOSTCMSParser() as parser, pytest.raises(ParseError, match="not a PDF"):
        parser.parse(source, "application/pkcs7-mime")


def test_attached_mapped_non_pdf_fails_explicitly(tmp_path: Path) -> None:
    source = tmp_path / "mapped-content.p7m"
    source.write_bytes(_cms(b"not a PDF", encapsulated_content_type="signed_data"))

    with GOSTCMSParser() as parser, pytest.raises(ParseError, match="not a PDF"):
        parser.parse(source, "application/pkcs7-mime")


def test_metadata_selects_only_the_certificate_matching_issuer_and_serial(
    tmp_path: Path,
) -> None:
    source = tmp_path / "certificates.p7m"
    issuer = x509.Name.build({"common_name": "Synthetic Issuer"})
    decoy = _certificate(
        x509.Name.build({"common_name": "Decoy Issuer"}),
        serial_number=7,
        subject="Decoy Signer",
    )
    source.write_bytes(
        _cms(
            b"%PDF-1.7\n%%EOF\n",
            certificates=[decoy, _certificate(issuer)],
        ),
    )

    with GOSTCMSParser() as parser:
        metadata = parser.extract_metadata(source, "application/pkcs7-mime")

    assert {entry["value"] for entry in metadata if entry["key"] == "signer_subject"} == {
        "Common Name: Synthetic Signer",
    }
    assert {entry["value"] for entry in metadata if entry["key"] == "signer_issuer"} == {
        "Common Name: Synthetic Issuer",
    }


def test_metadata_omits_certificate_fields_without_a_matching_issuer_and_serial(
    tmp_path: Path,
) -> None:
    source = tmp_path / "no-matching-certificate.p7m"
    source.write_bytes(
        _cms(
            b"%PDF-1.7\n%%EOF\n",
            certificates=[
                _certificate(
                    x509.Name.build({"common_name": "Decoy Issuer"}),
                    serial_number=7,
                    subject="Decoy Signer",
                ),
            ],
        ),
    )

    with GOSTCMSParser() as parser:
        metadata = parser.extract_metadata(source, "application/pkcs7-mime")

    assert {entry["key"] for entry in metadata}.isdisjoint(
        {"signer_subject", "signer_issuer"},
    )


def test_safe_metadata_values_are_truncated_at_512_characters() -> None:
    assert _entry("signer_subject", "x" * 513)["value"] == "x" * 512


def _cms(
    content: bytes | None,
    *,
    digest_oid: str = "1.2.643.7.1.1.2.2",
    signature_oid: str = "1.2.643.7.1.1.3.2",
    encapsulated_content_type: str = "data",
    certificates: list[x509.Certificate] | None = None,
    signer_infos: list[dict[str, object]] | None = None,
) -> bytes:
    issuer = x509.Name.build({"common_name": "Synthetic Issuer"})
    if certificates is None:
        certificates = [_certificate(issuer)]
    if signer_infos is None:
        signer_infos = [_signer_info(issuer, digest_oid, signature_oid)]
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": digest_oid}],
            "encap_content_info": _encapsulated_content(
                content,
                encapsulated_content_type,
            ),
            "certificates": certificates,
            "signer_infos": signer_infos,
        },
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()


def _signer_info(
    issuer: x509.Name | None = None,
    digest_oid: str = "1.2.643.7.1.1.2.2",
    signature_oid: str = "1.2.643.7.1.1.3.2",
) -> dict[str, object]:
    issuer = issuer or x509.Name.build({"common_name": "Synthetic Issuer"})
    return {
        "version": "v1",
        "sid": {
            "issuer_and_serial_number": {
                "issuer": issuer,
                "serial_number": 42,
            },
        },
        "digest_algorithm": {"algorithm": digest_oid},
        "signed_attrs": [
            {
                "type": "signing_time",
                "values": [
                    cms.Time(
                        {
                            "utc_time": datetime.datetime(
                                2024,
                                1,
                                2,
                                3,
                                4,
                                5,
                                tzinfo=datetime.UTC,
                            ),
                        },
                    ),
                ],
            },
        ],
        "signature_algorithm": {"algorithm": signature_oid},
        "signature": b"synthetic signature",
    }


def _certificate(
    issuer: x509.Name,
    *,
    serial_number: int = 42,
    subject: str = "Synthetic Signer",
) -> x509.Certificate:
    signature_algorithm = algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    timestamp = datetime.datetime(2024, 1, 2, tzinfo=datetime.UTC)
    return x509.Certificate(
        {
            "tbs_certificate": {
                "version": "v3",
                "serial_number": serial_number,
                "signature": signature_algorithm,
                "issuer": issuer,
                "validity": {
                    "not_before": x509.Time({"utc_time": timestamp}),
                    "not_after": x509.Time({"utc_time": timestamp}),
                },
                "subject": x509.Name.build({"common_name": subject}),
                "subject_public_key_info": keys.PublicKeyInfo.wrap(
                    keys.RSAPublicKey({"modulus": 17, "public_exponent": 65537}),
                    "rsa",
                ),
            },
            "signature_algorithm": signature_algorithm,
            "signature_value": b"synthetic certificate signature",
        },
    )


def _encapsulated_content(
    content: bytes | None,
    content_type: str,
) -> dict[str, object]:
    if content is None:
        return {"content_type": content_type}
    if content_type == "data":
        return {"content_type": content_type, "content": content}
    return {
        "content_type": content_type,
        "content": cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": [],
                "encap_content_info": {"content_type": "data", "content": content},
                "signer_infos": [],
            },
        ),
    }
