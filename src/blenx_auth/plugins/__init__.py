"""Runtime plugins shipped with the library.

Each subpackage is a self-contained ``AuthPlugin`` (see
:mod:`blenx_auth.core.plugins`) that a host app enables with
``plugins=[make_two_factor_plugin(...)]`` — no manual class composition.
Plugins live here rather than under ``core``/``fastapi`` because they combine
schema mixins, storage mixins, services, and routers across both layers.
"""

__all__: list[str] = []
