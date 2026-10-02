# Development

```bash
go build -o bin/drop ./cmd/drop
go vet ./... && go test -race ./...
```

Run two instances on one machine with separate identities:

```bash
DROP_HOME=/tmp/drop-a drop receive --dir /tmp/inbox --yes
DROP_HOME=/tmp/drop-b drop --to <name-of-a> file.txt
```

Set `[device] name` in each `$DROP_HOME/config.toml` to tell them apart. Set the version with `-ldflags "-X github.com/thameem/drop/internal/cli.Version=1.2.3"`.

Conventions: wrap errors with context (`fmt.Errorf("...: %w", err)`); no terminal I/O outside `internal/cli`; never log keys or file contents.

## Make targets
`make build` · `make install` · `make test` (race detector) · `make vet` · `make smoke` (end-to-end test of the real binary, `scripts/smoke.sh`) · `make check` (all three). The smoke test is also the quickest way to confirm a fresh install works on a new machine.
