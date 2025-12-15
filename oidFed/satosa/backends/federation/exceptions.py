from oidFed.exceptions import ValidationError
from oidFed.satosa.backends.tools.http import HttpError


class TrustChainHttpError(HttpError):
    pass


class UnknownKid(Exception):
    pass


class MissingJwksClaim(Exception):
    pass


class MissingAuthorityHintsClaim(Exception):
    pass


class NotDescendant(Exception):
    pass


class TrustAnchorNeeded(Exception):
    pass


class MissingTrustAnchorPublicKey(Exception):
    pass


class MetadataDiscoveryException(Exception):
    pass


class MissingTrustMark(Exception):
    pass


class InvalidRequiredTrustMark(Exception):
    pass


class InvalidTrustchain(Exception):
    pass


class TrustchainMissingMetadata(Exception):
    pass


class InvalidEntityConfiguration(Exception):
    pass


class InvalidEntityStatement(Exception):
    pass


class TimeValidationError(Exception):
    pass


class KeyValidationError(Exception):
    pass


class InvalidChainError(Exception):
    pass


class ProtocolMetadataNotFound(Exception):
    pass


class InvalidEntityHeader(Exception):
    pass


class InvalidEntityStatementPayload(Exception):
    pass


class PolicyError(Exception):
    pass


class KidError(Exception):
    pass


class KidNotFoundError(Exception):
    pass


class InvalidJwk(Exception):
    pass


class InvalidKid(Exception):
    pass


class JWEDecryptionError(Exception):
    pass


class JWTInvalidElementPosition(Exception):
    pass


class JWSSigningError(Exception):
    pass


class JWSVerificationError(Exception):
    pass


class JWEEncryptionError(Exception):
    pass


class JWTDecodeError(Exception):
    pass


class NoTrustChainProvided(Exception):
    pass


class InvalidJwkMetadataException(Exception):
    pass


class UnknownTrustAnchor(Exception):
    pass


class MissingProtocolSpecificJwks(Exception):
    pass


class MissingTrustType(Exception):
    pass


class InvalidTrustType(Exception):
    pass


class InvalidAnchor(Exception):
    pass


class TrustConfigurationError(Exception):
    pass


class NoCriptographicMaterial(Exception):
    pass


class NoMetadata(Exception):
    pass


class LifetimeException(ValidationError):
    """Exception raised for errors related to lifetime validation."""
