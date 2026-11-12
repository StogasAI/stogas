from typing import Any, Literal, final

__all__ = [
    "EvidenceSnapshot",
    "EvidenceVerifier",
    "StreamContent",
    "Transport",
    "VerificationError",
    "VerifiedBoot",
    "request_digest",
    "response_digest",
]

class VerificationError(ValueError):
    """A failed verification. `code` is the stable reason that every binding shares."""

    code: str

@final
class Transport:
    """A managed transport whose `base_url` an OpenAI-compatible client uses."""

    def __new__(
        cls,
        *,
        environment: str = "prod",
        security: Literal["tls", "e2ee"] = "tls",
        max_connections: int = 4,
        base_url: str | None = None,
        proxy: str | None = None,
        onion: bool = False,
        encryption_keys: dict[str, str] | None = None,
    ) -> Transport: ...
    @property
    def base_url(self) -> str: ...
    def refresh_evidence(self) -> bool:
        """Refresh the evidence now, and return whether it changed."""
    def close(self) -> None: ...

@final
class EvidenceVerifier:
    def __new__(cls, *, environment: str = "prod", root: dict[str, Any] | None = None) -> EvidenceVerifier:
        """Without `root`, trusts the compiled Stogas root. A `root` is a root document, as an
        environment's root file gives it."""
    def refresh(self, evidence: bytes) -> EvidenceSnapshot: ...
    def verify_evidence_archive(self, evidence: bytes) -> bytes:
        """Authenticate archived evidence without installing it as current permission. Returns
        JSON."""
    def verify_boot_archive(self, archive: bytes, evidence: bytes) -> VerifiedBoot:
        """Appraise a boot at its authenticated log time. This grants no live authorization."""

@final
class EvidenceSnapshot:
    def summary(self) -> bytes:
        """The verified evidence's summary, as JSON."""
    def require_current_keys(self) -> None: ...
    def verify_logged_boot(self, document: bytes, inclusion: bytes) -> VerifiedBoot: ...

@final
class VerifiedBoot:
    def summary(self) -> bytes:
        """The verified boot's summary, as JSON."""
    def verify_receipt(
        self, document: bytes, request_digest: bytes | None = None, response_digest: bytes | None = None
    ) -> bytes:
        """Verify a final Stogas metadata object, salts included, against digests from
        `request_digest` and `response_digest`. A side without a digest stays unchecked. Returns
        the verified receipt as JSON."""
    def verify_stream(self, request_digest: bytes, stream: bytes) -> bytes:
        """Verify a complete saved stream, keepalives and its receipt included, against the
        request's digest. Returns JSON."""
    def verify_response(self, request_digest: bytes, response_body: bytes) -> bytes:
        """Verify a buffered response containing its final Stogas metadata object. Returns
        JSON."""

@final
class StreamContent:
    """A stream's events, read into the response that its receipt signs."""

    def __new__(cls) -> StreamContent: ...
    def push(self, event: bytes) -> None:
        """Read one complete event as it was sent. After an error every later call fails."""
    def digest(self) -> bytes:
        """The 64-byte digest of the response that the complete stream carries, for
        `VerifiedBoot.verify_receipt`. Every later call fails."""

def request_digest(body: bytes) -> bytes:
    """SHA-512 of the request body's RFC 8785 form without the top-level `encryption_keys`."""

def response_digest(body: bytes) -> bytes:
    """SHA-512 of a buffered response body's RFC 8785 form without the top-level `stogas`
    object."""
