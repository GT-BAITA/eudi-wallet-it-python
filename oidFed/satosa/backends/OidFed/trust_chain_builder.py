import datetime
import json
import logging
from collections import OrderedDict
from typing import Union

from oidFed.satosa.backends.federation.exceptions import (
    InvalidEntityStatement,
    InvalidRequiredTrustMark,
    MetadataDiscoveryException,
)
from oidFed.satosa.backends.federation.policy import TrustChainPolicy
from oidFed.satosa.backends.federation.statements import (
    EntityStatement,
    get_entity_configurations,
)
from oidFed.satosa.backends.tools.utils import datetime_from_timestamp

logger = logging.getLogger(__name__)


class TrustChainBuilder:
    """
    A trust walker that fetches statements and evaluate the evaluables
    """

    def __init__(
        self,
        subject: str,
        trust_anchor: str,
        httpc_params: dict,
        trust_anchor_configuration: Union[EntityStatement, str, None] = None,
        max_authority_hints: int = 10,
        subject_configuration: EntityStatement | None = None,
        required_trust_marks: list[dict] = [],
        # TODO - prefetch cache?
        # pre_fetched_entity_configurations = {},
        # pre_fetched_statements = {},
        **kwargs,
    ) -> None:
        """
        Initialized a TrustChainBuilder instance

        :parameter subject: represents the subject url (leaf) of the Trust Chain
        :type subject: str
        :parameter trust_anchor: represents the issuer url (leaf) of the Trust Chain
        :type trust_anchor: str
        :param httpc_params: parameters needed to perform http requests
        :type httpc_params: dict
        :param trust_anchor_configuration: is the entity statement configuration of Trust Anchor.
        The assigned value can be an EntityStatement, a str or None.
        If the value is a string it will be converted in an EntityStatement instance.
        If the value is None it will be retrieved from an http request on the trust_anchor field.
        :parameter max_authority_hints: the number of how many authority_hints to follow on each hop
        :type max_authority_hints: int
        :parameter subject_configuration: the configuration of subject
        :type subject_configuration: EntityStatement
        :parameter required_trust_marks: means all the trust marks needed to start a metadata discovery
        at least one of the required trust marks is needed to start a metadata discovery
        if this param if absent the filter won't be considered.
        :type required_trust_marks: list[dict]
        """
        self.subject = subject
        self.subject_configuration = subject_configuration
        self.httpc_params = httpc_params
        self.trust_anchor = trust_anchor

        if isinstance(trust_anchor_configuration, str):
            self.trust_anchor_configuration = EntityStatement(
                trust_anchor_configuration, httpc_params=httpc_params
            )
        else:
            self.trust_anchor_configuration = trust_anchor_configuration

        self.required_trust_marks = required_trust_marks
        self.is_valid = False

        self.tree_of_trust = OrderedDict()
        self.trust_path = []  # list of valid subjects up to trust anchor

        self.max_authority_hints = max_authority_hints
        # dynamically valued
        self.max_path_len = 10
        self.final_metadata: dict = {}

        self.verified_trust_marks = []
        self.exp = 0

    def apply_metadata_policy(self) -> dict:
        """
        filters the trust path from subject to trust anchor
        apply the metadata policies along the path.

        :returns: the final metadata with policy applied
        :rtype: dict
        """
        if not self.trust_path:
            self.trust_path = [self.subject_configuration]

        if self.trust_path[-1].sub == self.trust_anchor_configuration.sub:
            return self.final_metadata

        logger.info(
            f"Applying metadata policy for {self.subject} over "
            f"{self.trust_anchor_configuration.sub} starting from "
            f"{self.trust_path[-1].sub}"
        )

        path_found = self._find_trust_path()

        if path_found:
            logger.info(f"Found a trust path: {[ec.sub for ec in self.trust_path]}")

            self.final_metadata = self.subject_configuration.payload.get("metadata", {})
            if not self.final_metadata:
                logger.error(f"Missing metadata in subject configuration")
                return {}

            self._apply_policies_along_path()

            self._set_exp()

        return self.final_metadata

    def _find_trust_path(self) -> bool:
        current_level = 0

        while current_level < len(self.tree_of_trust):
            current_ecs = self.tree_of_trust[current_level]

            for ec in current_ecs:
                if ec.sub == self.trust_anchor_configuration.sub:
                    self.trust_path.append(ec)
                    return True

                if ec.verified_by_superiors:
                    for sup_ec in ec.verified_by_superiors.values():
                        if sup_ec.sub not in [e.sub for e in self.trust_path]:
                            self.trust_path.append(sup_ec)

                            if self._find_trust_path():
                                return True

                            self.trust_path.pop()

            current_level += 1

        return False

    def _apply_policies_along_path(self) -> None:
        """Aplica políticas de metadados ao longo do caminho de confiança"""
        for i in range(len(self.trust_path) - 1, 0, -1):
            superior = self.trust_path[i]
            inferior = self.trust_path[i - 1]

            policies = superior.verified_descendant_statements.get(
                inferior.sub, {}
            ).get("metadata_policy", {})

            if policies and self.final_metadata:
                for md_type, policy in policies.items():
                    if md_type in self.final_metadata:
                        self.final_metadata[md_type] = TrustChainPolicy().apply_policy(
                            self.final_metadata[md_type], policy
                        )

    def _set_exp(self) -> None:
        """
        updates the internal exp field with the nearest
        expiration date found in the trust_path field
        """
        exps = [
            ec.payload.get("exp") for ec in self.trust_path if ec.payload.get("exp")
        ]
        if exps:
            self.exp = min(exps)

    def discovery(self) -> bool:
        """
        discovers the chain of verified statements
        from the lower up to the trust anchor and updates
        the internal representation of chain.

        :returns: the validity status of the updated chain
        :rtype: bool
        """
        logger.info(f"Starting a Walk into Metadata Discovery for {self.subject}")

        if not self.subject_configuration:
            logger.error("Subject configuration not initialized")
            return False

        self.tree_of_trust[0] = [self.subject_configuration]

        ecs_history = []
        current_level = 0

        while current_level < self.max_path_len:
            if current_level not in self.tree_of_trust:
                break

            current_ecs = self.tree_of_trust[current_level]
            next_ecs = []

            for ec in current_ecs:
                if ec.sub in ecs_history:
                    logger.warning(
                        f"Metadata discovery loop detection for {ec.sub}. "
                        "Discovery blocked for this path."
                    )
                    continue

                try:
                    superiors = ec.get_superiors(
                        max_authority_hints=self.max_authority_hints,
                        superiors_hints=(
                            [self.trust_anchor_configuration]
                            if self.trust_anchor_configuration
                            else []
                        ),
                    )

                    validated_by = ec.validate_by_superiors(
                        superiors_entity_configurations=superiors.values()
                    )

                    for sup_ec in validated_by.values():
                        if sup_ec not in next_ecs:
                            next_ecs.append(sup_ec)

                    ecs_history.append(ec.sub)

                except MetadataDiscoveryException as e:
                    logger.exception(f"Metadata discovery exception for {ec.sub}: {e}")
                except Exception as e:
                    logger.error(f"Error during discovery for {ec.sub}: {e}")

            if next_ecs:
                self.tree_of_trust[current_level + 1] = next_ecs
                current_level += 1
            else:
                break

        for level, ecs in self.tree_of_trust.items():
            for ec in ecs:
                if ec.sub == self.trust_anchor_configuration.sub:
                    self.is_valid = True
                    break

        if self.is_valid:
            self.apply_metadata_policy()

        return self.is_valid

    def get_trust_anchor_configuration(self) -> None:
        """
        Download and updates the internal field trust_anchor_configuration
        with the entity statement of trust anchor.
        """

        if self.trust_anchor_configuration:
            try:
                self.trust_anchor_configuration.validate_by_itself()
                self._set_max_path_len()
                return
            except Exception:
                logger.warning(
                    "Existing trust anchor configuration is invalid, fetching new one"
                )

        try:
            logger.info(
                f"Getting Trust Anchor Entity Configuration for {self.trust_anchor}"
            )
            ta_jwts = get_entity_configurations(
                self.trust_anchor, httpc_params=self.httpc_params
            )

            if not ta_jwts:
                raise Exception("No entity configuration found for trust anchor")

            ta_jwt = ta_jwts[0]
            self.trust_anchor_configuration = EntityStatement(
                ta_jwt, httpc_params=self.httpc_params
            )

            self.trust_anchor_configuration.validate_by_itself()
            self._set_max_path_len()

        except Exception as e:
            _msg = (
                f"Trust Anchor Entity Configuration failed for {self.trust_anchor}: {e}"
            )
            logger.error(_msg)
            raise Exception(_msg)

    def _set_max_path_len(self) -> None:
        """
        Sets the internal field max_path_len with the constraint
        found in trust anchor payload
        """
        if (
            self.trust_anchor_configuration
            and self.trust_anchor_configuration.payload.get("constraints", {}).get(
                "max_path_length"
            )
        ):
            self.max_path_len = int(
                self.trust_anchor_configuration.payload["constraints"][
                    "max_path_length"
                ]
            )
        else:
            self.max_path_len = 10

    def get_subject_configuration(self) -> None:
        """
        Download and updates the internal field subject_configuration
        with the entity statement of leaf.
        """
        if not self.subject_configuration:
            try:
                logger.info(f"Getting Subject Entity Configuration for {self.subject}")
                jwts = get_entity_configurations(
                    self.subject, httpc_params=self.httpc_params
                )

                if not jwts:
                    raise Exception("No entity configuration found for subject")

                jwt = jwts[0]
                self.subject_configuration = EntityStatement(
                    jwt,
                    trust_anchor_entity_conf=self.trust_anchor_configuration,
                    httpc_params=self.httpc_params,
                )

                self.subject_configuration.validate_by_itself()

                if self.required_trust_marks:
                    sc = self.subject_configuration
                    sc.filter_by_allowed_trust_marks = self.required_trust_marks

                    if not sc.validate_by_allowed_trust_marks():
                        raise InvalidRequiredTrustMark(
                            "The required Trust Marks are not valid"
                        )
                    else:
                        self.verified_trust_marks.extend(sc.verified_trust_marks)

            except Exception as e:
                _msg = f"Entity Configuration for {self.subject} failed: {e}"
                logger.error(_msg)
                raise InvalidEntityStatement(_msg)

    def serialize(self) -> str:
        """
        Serializes the chain in JSON format.

        :returns: the serialized chain in JSON format
        :rtype: str
        """
        return json.dumps(self.get_trust_chain())

    def get_trust_chain(self) -> list[str]:
        """
        Retrieves the leaf and the Trust Anchor entity configurations.

        :returns: the list containing the ECs
        :rtype: list[str]
        """
        res = []

        if not self.trust_path:
            return res

        for stat in self.trust_path:
            if stat.sub == self.subject:
                res.append(stat.jwt)
                break

        for stat in self.trust_path:
            if stat.verified_descendant_statements_as_jwt:
                for jwt in stat.verified_descendant_statements_as_jwt.values():
                    if jwt not in res:
                        res.append(jwt)

        for stat in self.trust_path:
            if stat.sub == self.trust_anchor_configuration.sub:
                res.append(stat.jwt)
                break

        return res

    def start(self):
        """
        Retrieves the subject (leaf) configuration and starts
        chain discovery.

        :returns: the list containing the ECs
        :rtype: list[str]
        """
        try:
            self.get_trust_anchor_configuration()

            self.get_subject_configuration()

            if self.subject_configuration and self.trust_anchor_configuration:
                self.subject_configuration.update_trust_anchor_conf(
                    self.trust_anchor_configuration
                )

            self.discovery()

            return self.get_trust_chain()

        except Exception as e:
            self.is_valid = False
            logger.error(f"Trust chain building failed: {e}")
            raise e

    @property
    def exp_datetime(self) -> datetime.datetime:
        """The exp field converted in datetime format"""
        if self.exp:
            return datetime_from_timestamp(self.exp)
        return None
