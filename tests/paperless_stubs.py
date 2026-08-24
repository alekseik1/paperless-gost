from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import TypedDict


class ParseError(Exception):
    pass


class MetadataEntry(TypedDict):
    namespace: str
    prefix: str
    key: str
    value: str


@dataclass(frozen=True, slots=True)
class ParserContext:
    mailrule_id: int | None = None


class _ParserProtocolMeta(type):
    def __instancecheck__(self, instance: object) -> bool:
        return all(
            hasattr(instance, attribute)
            for attribute in (
                "name",
                "version",
                "author",
                "url",
                "supported_mime_types",
                "score",
                "can_produce_archive",
                "requires_pdf_rendition",
                "configure",
                "parse",
                "get_text",
                "get_date",
                "get_archive_path",
                "get_thumbnail",
                "get_page_count",
                "extract_metadata",
            )
        )


class ParserProtocol(metaclass=_ParserProtocolMeta):
    pass


def get_default_thumbnail() -> Path:
    return Path(__file__)


def make_thumbnail_from_pdf(in_path: Path, temp_dir: Path) -> Path:
    return temp_dir / "thumbnail.webp"


def install_paperless_stubs() -> None:
    documents = ModuleType("documents")
    documents.__path__ = []
    document_parsers = ModuleType("documents.parsers")
    document_parsers.ParseError = ParseError
    document_parsers.get_default_thumbnail = get_default_thumbnail
    document_parsers.make_thumbnail_from_pdf = make_thumbnail_from_pdf
    paperless = ModuleType("paperless")
    paperless.__path__ = []
    paperless_parsers = ModuleType("paperless.parsers")
    paperless_parsers.MetadataEntry = MetadataEntry
    paperless_parsers.ParserContext = ParserContext
    paperless_parsers.ParserProtocol = ParserProtocol
    sys.modules["documents"] = documents
    sys.modules["documents.parsers"] = document_parsers
    sys.modules["paperless"] = paperless
    sys.modules["paperless.parsers"] = paperless_parsers
