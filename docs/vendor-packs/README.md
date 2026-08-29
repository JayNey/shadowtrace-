# Vendor packs

Adapter-layer contracts live under [`contracts/vendor/`](../../contracts/vendor/). Kernel Agent code must not contain vendor paths, field names, or signing headers.

## Sangfor XDR

- Alignment plan (layers, dual runtime, hard rules): [`docs/sangfor-xdr-alignment-plan.md`](../sangfor-xdr-alignment-plan.md)
- Machine-readable OpenAPI extract (129 operations): [`contracts/vendor/sangfor_xdr/catalog.json`](../../contracts/vendor/sangfor_xdr/catalog.json)
- Product-loop matrix (`in_loop` / `role`): [`contracts/vendor/sangfor_xdr/capability_matrix.yaml`](../../contracts/vendor/sangfor_xdr/capability_matrix.yaml)
- Source HTML: `挑战杯物料/OpenAPIDocument/深信服XDR平台接口开放列表.html`
- Refresh catalog: `python3 scripts/extract_sangfor_catalog.py`
- Drift gate: `python3 scripts/check_sangfor_catalog_drift.py`

Canonical Mock stays on `/mock-xdr/v1`. Do not rewrite Mock URIs to look like Sangfor. Overlay from this matrix must not default onto `KIND=mock`.

P0 / Demo remains the Mock gold path (isolate / disable_account / full `query_*` intact). Cutover-Ready is not live verification: Layer 10 has not been run against production XDR in this repo. Live investigation query (Layer 8b Query Provider) is not wired — do not describe it as complete.
