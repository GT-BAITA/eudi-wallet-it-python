import logging
from typing import Any, Callable, List
from satosa.context import Context
from satosa.response import Response

from oidFed.trust.exceptions import NoMetadata
from oidFed.trust.handler.interface import TrustHandlerInterface
from oidFed.tools.utils import dynamic_class_loader

logger = logging.getLogger(__name__)


class SimpleTrustEvaluator:
    """
    Versão simplificada do CombinedTrustEvaluator focada apenas em registrar endpoints
    """

    def __init__(self, handlers: List[TrustHandlerInterface]) -> None:
        """
        Initialize the SimpleTrustEvaluator.

        :param handlers: The trust handlers (apenas FederationHandler no seu caso)
        :type handlers: list[TrustHandlerInterface]
        """
        self.handlers: List[TrustHandlerInterface] = handlers

    def build_metadata_endpoints(
        self, backend_name: str, entity_uri: str
    ) -> List[tuple[str, Callable[[Context, Any], Response]]]:
        """
        Coleta todos os endpoints de metadados dos handlers (ex: .well-known)
        
        :param backend_name: Nome do backend (ex: "OpenID4VP")
        :param entity_uri: URL base da entidade
        :return: Lista de endpoints para registro
        """
        endpoints = []
        
        for handler in self.handlers:
            handler_endpoints = handler.build_metadata_endpoints(backend_name, entity_uri)
            endpoints.extend(handler_endpoints)
            
            # Log para debug
            for path, _ in handler_endpoints:
                logger.info(f"Trust handler {handler.__class__.__name__} registrou endpoint: {path}")
        
        return endpoints

    @staticmethod
    def from_config(config: dict, default_client_id: str) -> "SimpleTrustEvaluator":
        """
        Cria um SimpleTrustEvaluator a partir da configuração.
        Versão simplificada do método original.
        
        :param config: Configuração de trust do YAML
        :param default_client_id: Client ID padrão
        :return: Instância do SimpleTrustEvaluator
        """
        handlers = []
        
        for handler_name, handler_config in config.items():
            try:
                # Configura o client_id
                client_id = handler_config["config"].get("client_id")
                issuer_id = handler_config["config"].get("issuer_id")
                
                if client_id and issuer_id:
                    raise ValueError(f"{handler_name}: client_id e issuer_id ambos configurados")
                
                if not client_id and not issuer_id:
                    handler_config["config"]["client_id"] = default_client_id
                else:
                    handler_config["config"]["client_id"] = client_id or issuer_id

                # Carrega o handler dinamicamente
                trust_handler = dynamic_class_loader(
                    handler_config["module"],
                    handler_config["class"],
                    handler_config["config"],
                )

                if not isinstance(trust_handler, TrustHandlerInterface):
                    raise ValueError(f"Classe {trust_handler.__class__} não implementa TrustHandlerInterface")

                handlers.append(trust_handler)
                logger.info(f"Trust handler carregado: {handler_name}")

            except Exception as e:
                logger.error(f"Erro ao carregar trust handler {handler_name}: {e}")
                raise

        if not handlers:
            logger.warning("Nenhum trust handler configurado")

        return SimpleTrustEvaluator(handlers)
