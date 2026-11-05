//! Offline appraisal uses the same owned snapshots as the managed transport.

use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};
use std::sync::Arc;
use stogas_core::{
    authority::{Environment, RootKey},
    evidence::{self, boot::VerifiedBoot},
    receipt,
};

pyo3::create_exception!(stogas, VerificationError, PyValueError);

#[pyclass(name = "EvidenceVerifier")]
struct EvidenceVerifier {
    core: evidence::Verifier,
}

#[pyclass(name = "EvidenceSnapshot", frozen)]
struct EvidenceSnapshot {
    core: Arc<evidence::Snapshot>,
}

#[pyclass(name = "VerifiedBoot", frozen)]
struct Boot {
    core: VerifiedBoot,
}

/// A stream's events, read into the response that its receipt signs: the `chat.completion`
/// that Chat Completions chunks assemble to, or the `response` of a Responses stream's
/// terminal event.
#[pyclass(name = "StreamContent")]
struct StreamContent {
    core: Option<receipt::StreamContent>,
}

#[pymethods]
impl EvidenceVerifier {
    /// Without `root`, trusts the compiled Stogas root. A `root` is a root document, as an
    /// environment's root file gives it.
    #[new]
    #[pyo3(signature = (*, environment = "prod", root = None))]
    fn new(py: Python<'_>, environment: &str, root: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let environment: Environment = serde_json::from_value(serde_json::json!(environment))
            .map_err(|_| PyValueError::new_err("environment is unsupported by this build"))?;
        let core = match root {
            None => evidence::Verifier::stogas(environment),
            Some(root) => {
                let text: String = py
                    .import("json")?
                    .call_method1("dumps", (root,))?
                    .extract()?;
                let root: RootKey = serde_json::from_str(&text)
                    .map_err(|_| PyValueError::new_err("invalid root key"))?;
                evidence::Verifier::new(environment, root)
            }
        }
        .map_err(|error| evidence_error(py, &error))?;
        Ok(Self { core })
    }

    fn refresh(
        &mut self,
        py: Python<'_>,
        evidence: &Bound<'_, PyBytes>,
    ) -> PyResult<EvidenceSnapshot> {
        let bytes = evidence.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.refresh(bytes, now))
            .map(|core| EvidenceSnapshot { core })
            .map_err(|error| evidence_error(py, &error))
    }

    /// Authenticate archived evidence without installing it as current permission.
    fn verify_evidence_archive<'py>(
        &self,
        py: Python<'py>,
        evidence: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let evidence = evidence.as_bytes();
        let now = super::wall_clock_ms()?;
        let result = py
            .detach(|| self.core.verify_evidence_archive(evidence, now))
            .map_err(|error| evidence_error(py, &error))?;
        super::json_bytes(py, &result)
    }

    /// Appraise a boot at its authenticated log time. This grants no live authorization.
    fn verify_boot_archive(
        &self,
        py: Python<'_>,
        archive: &Bound<'_, PyBytes>,
        evidence: &Bound<'_, PyBytes>,
    ) -> PyResult<Boot> {
        let archive = archive.as_bytes();
        let evidence = evidence.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.verify_boot_archive(archive, evidence, now))
            .map(|core| Boot { core })
            .map_err(|error| evidence_error(py, &error))
    }
}

#[pymethods]
impl EvidenceSnapshot {
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        super::json_bytes(py, &self.core.summary())
    }

    fn require_current_keys(&self, py: Python<'_>) -> PyResult<()> {
        self.core
            .require_current_keys()
            .map_err(|error| evidence_error(py, &error))?;
        self.core
            .evidence()
            .valid_until(super::wall_clock_ms()?)
            .map_err(|error| evidence_error(py, &evidence::Error::from(error)))?;
        Ok(())
    }

    fn verify_logged_boot(
        &self,
        py: Python<'_>,
        document: &Bound<'_, PyBytes>,
        inclusion: &Bound<'_, PyBytes>,
    ) -> PyResult<Boot> {
        let document = document.as_bytes();
        let inclusion = inclusion.as_bytes();
        let now = super::wall_clock_ms()?;
        py.detach(|| self.core.verify_logged_boot(document, inclusion, now))
            .map(|core| Boot { core })
            .map_err(|error| evidence_error(py, &error))
    }
}

#[pymethods]
impl Boot {
    fn summary<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        super::json_bytes(py, &self.core.summary())
    }

    /// Verify a final Stogas metadata object, salts included, against digests from
    /// `request_digest` and `response_digest`. A side without a digest stays unchecked.
    #[pyo3(signature = (document, request_digest=None, response_digest=None))]
    fn verify_receipt<'py>(
        &self,
        py: Python<'py>,
        document: &Bound<'_, PyBytes>,
        request_digest: Option<&Bound<'_, PyBytes>>,
        response_digest: Option<&Bound<'_, PyBytes>>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let document = document.as_bytes();
        let request = request_digest
            .map(|digest| content_digest(digest.as_bytes(), "request"))
            .transpose()?;
        let response = response_digest
            .map(|digest| content_digest(digest.as_bytes(), "response"))
            .transpose()?;
        let result = py
            .detach(|| {
                receipt::verify_metadata(document, &self.core, request.as_ref(), response.as_ref())
                    .map(|verified| verified.receipt)
            })
            .map_err(|error| receipt_error(py, &error))?;
        super::json_bytes(py, &result)
    }

    /// Verify a complete saved stream, keepalives and its receipt included, against the
    /// request's digest.
    fn verify_stream<'py>(
        &self,
        py: Python<'py>,
        request_digest: &Bound<'_, PyBytes>,
        stream: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let request = content_digest(request_digest.as_bytes(), "request")?;
        let stream = stream.as_bytes();
        let result = py
            .detach(|| {
                let mut reader = receipt::Stream::new(request);
                reader.push(stream)?;
                reader.finish(&self.core)
            })
            .map_err(|error| receipt_error(py, &error))?;
        super::json_bytes(py, &result)
    }

    /// Verify a buffered response containing its final Stogas metadata object.
    fn verify_response<'py>(
        &self,
        py: Python<'py>,
        request_digest: &Bound<'_, PyBytes>,
        response_body: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let request = content_digest(request_digest.as_bytes(), "request")?;
        let response = response_body.as_bytes();
        let result = py
            .detach(|| receipt::verify_buffered(&self.core, &request, response))
            .map_err(|error| receipt_error(py, &error))?;
        super::json_bytes(py, &result)
    }
}

#[pymethods]
impl StreamContent {
    #[new]
    fn new() -> Self {
        Self {
            core: Some(receipt::StreamContent::default()),
        }
    }

    /// Read one complete event as it was sent, with or without its closing blank line. A block
    /// of comments, such as a keepalive or the receipt, changes nothing. After an error every
    /// later call fails.
    fn push(&mut self, py: Python<'_>, event: &Bound<'_, PyBytes>) -> PyResult<()> {
        let reader = self.core.as_mut().ok_or_else(stopped)?;
        let event = event.as_bytes();
        if let Err(error) = py.detach(|| reader.push(event)) {
            self.core = None;
            return Err(receipt_error(py, &error));
        }
        Ok(())
    }

    /// The 64-byte digest of the response that the complete stream carries, for
    /// `VerifiedBoot.verify_receipt`. Every later call fails.
    fn digest<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let reader = self.core.take().ok_or_else(stopped)?;
        let digest = py
            .detach(|| reader.digest())
            .map_err(|error| receipt_error(py, &error))?;
        Ok(PyBytes::new(py, &digest))
    }
}

fn stopped() -> PyErr {
    PyValueError::new_err("the stream reader has already given its digest or failed")
}

/// The digest that a receipt commits a request body to: SHA-512 of its RFC 8785 form without
/// the top-level `encryption_keys`.
#[pyfunction]
fn request_digest<'py>(
    py: Python<'py>,
    body: &Bound<'_, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let body = body.as_bytes();
    let digest = py
        .detach(|| receipt::request_digest(body))
        .map_err(|error| receipt_error(py, &receipt::Error::Canonical(error)))?;
    Ok(PyBytes::new(py, &digest))
}

/// The digest that a receipt commits a buffered response body to: SHA-512 of its RFC 8785 form
/// without the top-level `stogas` object.
#[pyfunction]
fn response_digest<'py>(
    py: Python<'py>,
    body: &Bound<'_, PyBytes>,
) -> PyResult<Bound<'py, PyBytes>> {
    let body = body.as_bytes();
    let digest = py
        .detach(|| receipt::response_digest(body))
        .map_err(|error| receipt_error(py, &receipt::Error::Canonical(error)))?;
    Ok(PyBytes::new(py, &digest))
}

fn content_digest(bytes: &[u8], side: &str) -> PyResult<receipt::ContentDigest> {
    bytes
        .try_into()
        .map_err(|_| PyValueError::new_err(format!("{side} digest must be 64 bytes")))
}

fn evidence_error(py: Python<'_>, error: &evidence::Error) -> PyErr {
    coded_error(py, error.code(), error.to_string())
}

fn receipt_error(py: Python<'_>, error: &receipt::Error) -> PyErr {
    coded_error(py, error.code(), error.to_string())
}

pub fn coded_error(py: Python<'_>, code: &str, message: String) -> PyErr {
    let error = VerificationError::new_err(message);
    match error.value(py).setattr("code", code) {
        Ok(()) => error,
        Err(error) => error,
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<EvidenceVerifier>()?;
    module.add_class::<EvidenceSnapshot>()?;
    module.add_class::<Boot>()?;
    module.add_class::<StreamContent>()?;
    module.add_function(wrap_pyfunction!(request_digest, module)?)?;
    module.add_function(wrap_pyfunction!(response_digest, module)?)?;
    module.add(
        "VerificationError",
        module.py().get_type::<VerificationError>(),
    )
}
