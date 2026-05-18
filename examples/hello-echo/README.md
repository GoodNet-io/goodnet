# hello-echo — minimum GoodNet client + server

Reference "hello world" for DX comparison. The two source files
target the GoodNet SDK as it's recommended today — modern sugar
(`gn::sdk::connect_to`, `gn::sdk::listen_to`, `Subscription`,
`Subscription::on_data_any`) so the LOC count reflects the
current API, not the verbose pre-sugar shape.

Source-only — these files are **NOT built** (`examples/CMakeLists.txt`
adds `two_node` + `bench` only). The `host_api_default()` call in
both is a placeholder for the operator-provided `host_api_t*` (a
real embedding wires this through `build_host_api` against a kernel
the embedder constructs; see `examples/two_node/main.cpp` for the
canonical embedding shape). The placeholder keeps the LOC count
honest — it counts the lines an SDK consumer writes, not the
embedder glue.

The matching reference for other stacks lives in
`bench/comparison/setup/` — each `setup/*.sh` fetches the
upstream "hello echo" sample for that stack so the LOC counter
(`bench/comparison/runners/dx_loc_count.sh`) has files to count.
