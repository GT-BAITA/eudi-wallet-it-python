import uuid
from datetime import datetime
from typing import Callable, Tuple, Union

from oidFed.storage.base_db import BaseDB
from oidFed.storage.base_cache import BaseCache, RetrieveStatus
from oidFed.storage.base_storage import BaseStorage, TrustType
from oidFed.storage.exceptions import ChainNotExist, EntryNotFound, StorageWriteError

from oidFed.tools.base_logger import BaseLogger
from oidFed.tools.utils import dynamic_class_loader



class DBEngine(BaseStorage, BaseCache, BaseLogger):
    """
    DB Engine class for OIDC Federation.
    """

    def __init__(self, config: dict):
        self.caches: list[Tuple[str, BaseCache]] = []
        self.storages: list[Tuple[str, BaseStorage]] = []

        for db_name, db_conf in config.items():
            storage_instance, cache_instance = self._handle_instance(db_conf)

            if storage_instance:
                self.storages.append((db_name, storage_instance))

            if cache_instance:
                self.caches.append((db_name, cache_instance))

    def close(self):
        self._close_list(self.storages)
        self._close_list(self.caches)

    def write(self, method: str, *args, **kwargs):
        replica_count = 0
        _err_msg = f"Cannot apply write method '{method}' with {args} {kwargs}"
        for db_name, storage in self.storages:
            try:
                getattr(storage, method)(*args, **kwargs)
                replica_count += 1
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__, f"Error {_err_msg} on {db_name}: {e}"
                )

        if not replica_count:
            raise StorageWriteError(_err_msg)
        return replica_count

    def get(self, method: str, *args, **kwargs) -> Union[dict, None]:
        for db_name, storage in self.storages:
            try:
                res = getattr(storage, method)(*args, **kwargs)
                if res:
                    return res
            except EntryNotFound as e:
                self._log_debug(
                    e.__class__.__name__,
                    f"Cannot find result by method {method} on {db_name}: {str(e)}",
                )
        raise EntryNotFound(f"Cannot find any result by method {method}")

    def init_session(self, session_id: str, state: str, remote_flow_typ: str) -> str:
        document_id = str(uuid.uuid4())
        for db_name, storage in self.storages:
            try:
                storage.init_session(
                    document_id,
                    session_id=session_id,
                    state=state,
                    remote_flow_typ=remote_flow_typ,
                )
            except StorageWriteError as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Error initializing session {document_id} on {db_name}: {e}"
                )
                raise e
        return document_id

    def get_by_session_id(self, session_id: str) -> Union[dict, None]:
        return self.get("get_by_session_id", session_id=session_id)

    def upsert_session(self, session_id: str, data: dict) -> int:
        return self.write("upsert_session", session_id, data)
    
    def search_session_by_field(self, field: str, value: str) -> dict | None:
        return self.get("search_session_by_field", field, value)

    def set_finalized(self, document_id: str):
        return self.write("set_finalized", document_id)

    def get_trust_attestation(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_attestation", entity_id)

    def get_trust_anchor(self, entity_id: str) -> Union[dict, None]:
        return self.get("get_trust_anchor", entity_id)

    def get_trust_source(self, entity_id: str) -> dict:
        return self.get("get_trust_source", entity_id)

    def has_trust_attestation(self, entity_id: str) -> bool:
        return self.get_trust_attestation(entity_id) is not None

    def has_trust_anchor(self, entity_id: str) -> bool:
        return self.get_trust_anchor(entity_id) is not None

    def has_trust_source(self, entity_id: str) -> bool:
        return self.get_trust_source(entity_id) is not None

    def add_trust_attestation(
        self,
        entity_id: str,
        attestation: list[str] = [],
        exp: datetime = None,
        trust_type: TrustType = TrustType.FEDERATION,
        jwks: list[dict] = [],
    ) -> str:
        return self.write(
            "add_trust_attestation", entity_id, attestation, exp, trust_type, jwks
        )

    def add_trust_attestation_metadata(
        self, entity_id: str, metadat_type: str, metadata: dict
    ) -> str:
        return self.write(
            "add_trust_attestation_metadata", entity_id, metadat_type, metadata
        )

    def add_trust_source(self, trust_source: dict) -> str:
        return self.write("add_trust_source", trust_source)

    def add_empty_trust_anchor(self, entity_id: str) -> str:
        return self.write("add_empty_trust_anchor", entity_id)

    def add_trust_anchor(
        self,
        entity_id: str,
        entity_configuration: str,
        exp: datetime,
        trust_type: TrustType = TrustType.FEDERATION,
    ) -> str:
        return self.write(
            "add_trust_anchor", entity_id, entity_configuration, exp, trust_type
        )

    def update_trust_attestation(
        self,
        entity_id: str,
        attestation: list[str] = [],
        exp: datetime = None,
        trust_type: TrustType = TrustType.FEDERATION,
        jwks: list[dict] = [],
    ) -> str:
        return self.write(
            "update_trust_attestation", entity_id, attestation, exp, trust_type, jwks
        )

    def add_or_update_trust_attestation(
        self,
        entity_id: str,
        attestation: list[str] = [],
        exp: datetime = None,
        trust_type: TrustType = TrustType.FEDERATION,
        jwks: list[dict] = [],
    ) -> str:
        try:
            self.get_trust_attestation(entity_id)
            return self.update_trust_attestation(entity_id, attestation, exp, trust_type, jwks)
        except (EntryNotFound, ChainNotExist):
            return self.add_trust_attestation(entity_id, attestation, exp, trust_type, jwks)

    def update_trust_anchor(
        self,
        entity_id: str,
        entity_configuration: dict,
        exp: datetime,
        trust_type: TrustType = TrustType.FEDERATION,
    ) -> str:
        return self.write(
            "update_trust_anchor", entity_id, entity_configuration, exp, trust_type
        )

    def try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> dict:
        if not len(self.caches):
            return on_not_found()

        cache_object, status, idx = self._cache_try_retrieve(object_name, on_not_found)

        if status == RetrieveStatus.RETRIEVED:
            return cache_object

        replica_instances = self.caches[:idx] + self.caches[idx + 1:]
        for cache_name, cache in replica_instances:
            try:
                cache.set(cache_object)
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot replicate cache object {object_name} on {cache_name}",
                )
        return cache_object

    def overwrite(self, object_name: str, value_gen_fn: Callable[[], str]) -> dict:
        for cache_name, cache in self.caches:
            try:
                return cache.overwrite(object_name, value_gen_fn)
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot overwrite cache object {object_name} on {cache_name}",
                )
        return value_gen_fn()

    def _cache_try_retrieve(self, object_name: str, on_not_found: Callable[[], str]) -> tuple[dict, RetrieveStatus, int]:
        for i, (cache_name, cache_instance) in enumerate(self.caches):
            try:
                cache_object, status = cache_instance.try_retrieve(object_name, on_not_found)
                return cache_object, status, i
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Cannot retrieve cache object {object_name} on {cache_name}",
                )
        raise ConnectionRefusedError("Cannot retrieve cache object on any instance")

    def _close_list(self, db_list: list[Tuple[str, BaseDB]]) -> None:
        for db_name, db in db_list:
            try:
                db.close()
            except Exception as e:
                self._log_critical(
                    e.__class__.__name__,
                    f"Error closing db {db_name}: {e}",
                )
                raise e

    def _handle_instance(self, instance: dict) -> tuple[BaseStorage | None, BaseCache | None]:
        cache_conf = instance.get("cache", None)
        storage_conf = instance.get("storage", None)

        storage_instance = None
        if storage_conf:
            storage_instance = dynamic_class_loader(
                storage_conf["module"],
                storage_conf["class"],
                storage_conf.get("init_params", {}),
            )

        cache_instance = None
        if cache_conf:
            cache_instance = dynamic_class_loader(
                cache_conf["module"],
                cache_conf["class"],
                cache_conf.get("init_params", {}),
            )

        return storage_instance, cache_instance

    @property
    def is_connected(self):
        _connected = False
        _cons = {}
        for db_name, storage in self.storages:
            try:
                _connected = storage.is_connected
                _cons[db_name] = _connected
            except Exception as e:
                self._log_debug(
                    e.__class__.__name__,
                    f"Error checking connection on {db_name}: {e}",
                )

        if True in _cons.values() and not all(_cons.values()):
            self._log_warning(
                "DB Engine",
                f"Storage misalignment: {_cons}",
            )
        return _connected