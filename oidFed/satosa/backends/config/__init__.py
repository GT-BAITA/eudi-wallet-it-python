"""
Modulo de configuração para o backend OpenID Federation.
"""

import logging

from pydantic import ValidationError

from oidFed.satosa.backends.config.exeption import (
    ClientConfigError,
    ConfigError,
    FederationConfigError,
    NetworkConfigError,
)
from oidFed.satosa.backends.config.schemas.Client import ClientConfigSchema
from oidFed.satosa.backends.config.schemas.Federation import FederationConfigSchema
from oidFed.satosa.backends.config.schemas.network import NetworkConfigSchema

logger = logging.getLogger(__name__)


class Config:
    """
    Classe responsavel por armazenar e validar as configurações do modulo
    backend.

    Keyword arguments:
    config -- Um objeto de configuração contendo as definições necessárias
    para o backend.
    auth_callback_func -- Função padrão do satosa para callbacks.
    base_url -- URL base do satosa.
    name -- Nome do backend.
    """

    def __init__(self, config=None, auth_callback_func=None, base_url=None, name=None):
        logger.info("Configuração do proxy iniciada")

        if config is None:
            raise ConfigError("Configuração ausente")

        self.auth_callback_func = auth_callback_func
        self.base_url = base_url
        self.name = name
        self.jwt = config["jwt"]

        self.client = self.__set_verified_client_config(config=config)

        self.federation = self.__set_verified_federation_config(config=config)

        self.network = self.__set_verified_network_config(config=config)

        logger.info("Configuração do proxy finalizada")

    def __set_verified_client_config(self, config=None) -> dict:
        """
        Verifica se a configuração do cliente está completa e válida
        para ser consultada pelo proxy.

        Keyword arguments:
        config -- Um objeto de configuração contendo as definições necessárias
        para o backend.
        Return: dict -- A configuração do cliente verificada.
        """

        logger.info("Validando as configurações do client")

        if "client" not in config:
            raise ClientConfigError(
                "Configuração do cliente ausente no backend OpenID Federation."
            )

        try:
            ClientConfigSchema(**config["client"])
            logger.info("Configurações do client verificadas")
            logger.debug(f"client config: {config["client"]}")

            return config["client"]
        except ValidationError as e:
            raise ClientConfigError(f"Configuração do cliente inválida:\n{e}")

    def __set_verified_federation_config(self, config=None) -> dict:
        """
        Verifica se a configuração da federação está completa e válida
        para ser consultada pelo proxy.

        Keyword arguments:
        config -- Um objeto de configuração contendo as definições necessárias
        para o backend.
        Return: dict -- A configuração da federação verificada.
        """
        logger.info("Validando as configurações da federação")

        if "federation" not in config:
            raise FederationConfigError(
                "Configuração da federação ausente no backend OpenID Federation."
            )

        try:
            FederationConfigSchema(**config["federation"])
            logger.info("Configurações da federação verificadas")
            logger.debug(f"federation config: {config["federation"]}")

            return config["federation"]
        except ValidationError as e:
            raise FederationConfigError(f"Configuração da federação inválida:\n{e}")

    def __set_verified_network_config(self, config=None) -> dict:
        """sumary_line

        Keyword arguments:
        argument -- description
        Return: return_description
        """
        logger.info("Validando as configurações de network")
        try:
            NetworkConfigSchema(**config["network"])
            logger.info("Configurações da network verificadas")
            logger.debug(f"network config: {config["network"]}")

            return config["network"]
        except ValidationError as e:
            raise NetworkConfigError(f"Configuração da network inválida:\n{e}")
