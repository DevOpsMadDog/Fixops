# ssvc/plugins/

**Purpose:** Methodology-specific decision classes consumed by `DesignContextInjector`.

**Gotchas**
- Each methodology must expose a `Decision*` class; the injector discovers it via introspection.
- Keep plugin names lowercase to match overlay/CSV inputs.
