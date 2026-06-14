from homeassistant.helpers.json import JSONEncoder
from homeassistant.helpers.storage import Store
from homeassistant.util import json as json_util
from ..const import VERSION_STORAGE
from .logger import LOGGER
_LOGGER = LOGGER


class StateGridStore(Store):
    """A subclass of Store that allows multiple loads in the executor."""

    def load(self):
        """Load the data from disk if version matches."""
        try:
            data = json_util.load_json(self.path)
        except (
            BaseException
        ) as exception:
            _LOGGER.critical(
                "Could not load '%s', restore it from a backup or delete the file: %s",
                self.path,
                exception,
            )
        if data == {} or data["version"] != self.version:
            return None
        return data["data"]

    async def _async_migrate_func(self, old_version, old_minor_version, old_data):
        """版本迁移：存储版本不匹配时直接返回旧数据（不丢数据）。

        HA Store 在发现存储文件版本号与当前 VERSION_STORAGE 不一致时
        会调用此方法。如果不覆盖，默认 raise NotImplementedError，
        导致 save_data() 崩溃，整个登录流程被异常中断。
        """
        _LOGGER.warning(
            "存储版本迁移: %s.%s -> %s (数据保留不变)",
            old_version, old_minor_version, self.version,
        )
        # 不做任何数据结构变换，直接返回旧数据
        # 新版本的字段会在下次 save_data() 时补齐
        return old_data


def _get_store_for_key(hass, key, encoder):
    """Create a Store object for the key."""
    return StateGridStore(hass, VERSION_STORAGE, key, encoder=encoder, atomic_writes=True)


def get_store_for_key(hass, key):
    """Create a Store object for the key."""
    return _get_store_for_key(hass, key, JSONEncoder)


async def async_load_from_store(hass, key):
    """Load the retained data from store and return de-serialized data."""
    return await get_store_for_key(hass, key).async_load() or {}


async def async_save_to_store(hass, key, data):
    """Generate dynamic data to store and save it to the filesystem.

    The data is only written if the content on the disk has changed
    by reading the existing content and comparing it.

    If the data has changed this will generate two executor jobs

    If the data has not changed this will generate one executor job
    """
    try:
        current = await async_load_from_store(hass, key)
    except Exception as ex:
        _LOGGER.warning("读取存储文件失败，将覆盖保存: %s", ex)
        current = None
    if current is None or current != data:
        await get_store_for_key(hass, key).async_save(data)


async def async_remove_store(hass, key):
    """Remove a store element that should no longer be used."""
    if "/" not in key:
        return
    await get_store_for_key(hass, key).async_remove()
