class ClientConfigError(Exception):
    """
    Exceção lançada quando a configuração do cliente é inválida ou incompleta.
    """

    pass


class FederationConfigError(Exception):
    """
    Exceção lançada quando a configuração da federação é inválida ou incompleta.
    """

    pass


class NetworkConfigError(Exception):
    pass


class ConfigError(Exception):
    pass
