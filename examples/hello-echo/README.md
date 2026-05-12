# hello-echo — minimum GoodNet client + server

Reference "hello world" for DX comparison. The two source files
compile against the GoodNet SDK and use the modern sugar
(`gn::sdk::connect_to`, `gn::sdk::listen_to`, `Subscription`) so
the LOC count reflects the API as it's recommended today.

The matching reference for other stacks lives in
`bench/comparison/setup/` — each `setup/*.sh` fetches the
upstream "hello echo" sample for that stack so the LOC counter
(`bench/comparison/runners/dx_loc_count.sh`) has files to count.
