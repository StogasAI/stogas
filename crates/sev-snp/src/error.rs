use alloc::string::String;
use core::fmt;

/// The stage at which verification rejected its input. Bindings expose [`ErrorKind::code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The report's size, version, reserved fields or encoding is invalid.
    Report,
    /// The processor is not one that this crate verifies.
    UnsupportedProduct,
    /// The report carries no signature: the host masked the chip key, or no key signed it.
    Unsigned,
    /// An AMD certificate, certificate table or CRL is malformed or breaks AMD's profile.
    Certificate,
    /// A certificate, CRL or report signature is invalid.
    Signature,
    /// A certificate or CRL is not valid at the time given.
    Expired,
    /// AMD revoked the intermediate certificate.
    Revoked,
    /// The certificate does not match the report's processor, TCB, chip or signing key.
    Binding,
    /// The endorsement or CRL that the report or policy needs is absent.
    MissingEndorsement,
    /// The policy itself is invalid.
    InvalidPolicy,
    /// The verified report breaks the policy.
    Policy,
}

impl ErrorKind {
    /// A stable identifier for programs and other languages.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::UnsupportedProduct => "unsupported_product",
            Self::Unsigned => "unsigned",
            Self::Certificate => "certificate",
            Self::Signature => "signature",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Binding => "binding",
            Self::MissingEndorsement => "missing_endorsement",
            Self::InvalidPolicy => "invalid_policy",
            Self::Policy => "policy",
        }
    }
}

/// Why a report, endorsement or policy was rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The same as `self.kind().code()`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl core::error::Error for Error {}

macro_rules! constructors {
    ($($name:ident => $kind:ident),* $(,)?) => {
        $(
            pub fn $name(message: impl Into<String>) -> Error {
                Error::new(ErrorKind::$kind, message)
            }
        )*
    };
}

constructors! {
    report => Report,
    unsupported => UnsupportedProduct,
    unsigned => Unsigned,
    certificate => Certificate,
    signature => Signature,
    expired => Expired,
    revoked => Revoked,
    binding => Binding,
    missing => MissingEndorsement,
    invalid_policy => InvalidPolicy,
    policy => Policy,
}
