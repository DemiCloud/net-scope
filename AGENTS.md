# NetScope — Agent / Contributor Instructions

## Project Overview

NetScope (binary: `net-scope`) is a network inspection and reconnaissance tool combining
active probing, passive signal analysis, and change detection for LAN environments.
Written in Go 1.25.
It produces a **single binary per platform** from `cmd/net-scope/`.
The binary exposes all modes as subcommands:

```text
net-scope cli    [target] [flags]   # plain-text output — all platforms
net-scope tui    [target] [flags]   # Bubbletea TUI — Linux/BSD only
net-scope gui    [target]           # Gio GUI — Windows + Linux only
net-scope service <addr> <token>    # internal: sensor service subprocess
```

When run with **no subcommand**, the platform default is used unless
`default_mode` is set in `config.toml`:

| Platform | Default mode | Notes |
| --- | --- | --- |
| Windows (terminal) | `cli` | `AttachConsole` succeeds |
| Windows (double-click) | `gui` | No parent console |
| Linux | `cli` | Override via `default_mode = "gui"` or `"tui"` in config |
| FreeBSD / BSD | `cli` | GUI subcommand not available (no Gio backend) |

The old `cmd/cli/`, `cmd/tui/`, and `cmd/gui-win/` entry points still exist
and are buildable in isolation, but **the canonical entry point is
`cmd/net-scope/`**.

`cmd/gui-win/` is the **legacy Win32 GUI** — deprecated in favour of `cmd/gui-gio/`.
It is kept intact for reference and regression comparison during the Gio transition.
Do not add new features to `cmd/gui-win/`.

---

## Repository Layout

```text
cmd/
  net-scope/          ← unified entry point (build this)
    main.go           ← InitVendorDB + calls run()
    cli.go            ← runCLI() — all platforms
    tui_notwindows.go ← runTUI() — Linux/BSD only (!windows build tag)
    dispatch_windows.go ← subcommand dispatch; AttachConsole heuristic for default
    dispatch_other.go   ← subcommand dispatch; CLI default for Linux/BSD
  gui-gio/            ← package guigio — Gio-based GUI (Windows + Linux)
    main.go           ← Run(version, target string)
    ui.go             ← main window, layout, event loop
    service.go        ← sensor service IPC client (reusable; no Gio imports)
  gui-win/            ← package guiwin — DEPRECATED Win32 GUI (Windows only)
    (do not add new features here)
  gen-ico/            ← go run ./cmd/gen-ico/ → cmd/gui-win/icon.ico
  gen-rsrc/           ← go run ./cmd/gen-rsrc/ → cmd/gui-win/resource_windows_amd64.syso
  cli/                ← standalone CLI (legacy, keep for reference)
  tui/                ← standalone TUI (legacy, keep for reference)
internal/
  config/             ← TOML config; Load() never auto-writes on first run
  scan/               ← core scanner library; all wire types (ServiceCmd/ServiceMsg)
```

---

## Build Commands

```bash
# Dev builds
make linux           # → build/net-scope_linux_amd64
make windows         # → build/net-scope_windows_amd64.exe  (runs gen-resources first)
make bsd             # → build/net-scope_freebsd_amd64

# Regenerate icon.ico + resource_windows_amd64.syso (called automatically by make windows)
make gen-resources

# Stripped release builds → dist/ + checksums.txt
make release

# Tests / vet
make test
make vet
```

Cross-compilation is done from Linux (WSL Fedora).

| Target | CGo | Notes |
| --- | --- | --- |
| Windows (amd64) | **None** — `CGO_ENABLED=0` | Gio uses Direct3D 11 via pure syscalls |
| Linux (amd64) | Required — `gcc` + `wayland-devel libX11-devel mesa-libEGL-devel libxkbcommon-x11-devel` | Native build on Linux only |
| FreeBSD (amd64) | **None** — `CGO_ENABLED=0` | CLI / TUI only; no GUI |

The "no CGo" rule applies to **Windows and FreeBSD targets only**. CGo is acceptable for the Linux GUI target.

---

## Git Workflow

**After every meaningful change, make a commit.** This applies to:

- Bug fixes (including single-line corrections)
- New features or behaviour changes
- Refactors or code reorganisation
- Documentation / AGENTS.md updates
- Build / Makefile changes

Commit commands (run inside the Fedora WSL environment):

```bash
wsl -d Fedora -- bash -c "cd /home/lbreitk/dev/net-scope && git add <files> && git commit -m '<message>'"
```

Follow the conventional-commits style already used in the repo:

- `feat:` — new user-visible feature
- `fix:` — bug fix
- `refactor:` — internal restructure, no behaviour change
- `docs:` — documentation only
- `build:` — Makefile, generator, or toolchain changes
- `chore:` — everything else (dependency updates, file renames, etc.)

Do **not** push automatically; only commit locally unless the user explicitly asks to push.

**Before committing, check `TODO.md`** — if the change being committed completes or fixes something on the list, mark the relevant item(s) `[x]` and include `TODO.md` in the same commit.

**Keep the wiki up to date.** The wiki lives in `.wiki/` (a separate git repo, cloned locally). When a change affects user-visible behaviour documented there, update the relevant `.wiki/*.md` file in the same working session. If `.wiki/` is missing or empty, notify the operator — the wiki repo needs to be cloned first: `git clone https://github.com/demicloud/net-scope.wiki.git .wiki`

---

## Key Conventions

### Go

- **No CGo on Windows or FreeBSD targets.** The legacy Win32 GUI uses `syscall.NewLazyDLL` exclusively. The Gio Windows backend also uses pure syscalls. CGo is permitted for the Linux GUI target.
- All `cmd/gui-win/` files carry `//go:build windows` and `package guiwin`.
  Never change the package back to `main`.
- All `cmd/gui-gio/` files carry `package guigio` (no build constraint needed — Gio selects the right backend per platform automatically).
- Version is injected at link time: `-ldflags "-X main.version=<tag>"`.
  The variable lives in `cmd/net-scope/main.go` as `var version = "dev"`.
- `config.Load()` returns defaults silently when no file exists — it does
  **not** write a starter file. The GUI prompts on first save.

### GUI (all front-ends)

- **All network I/O goes through the sensor service subprocess — on every platform.**
  No GUI package (Win32 or Gio) may call scan functions, open sockets, or
  perform probing directly. The service IPC channel is the only allowed path.
  If a new feature touches the network, it belongs in `internal/scan/` and is
  invoked via `scan.ServiceCmd` / `scan.ServiceMsg`, not from a UI event handler.
- **The service IPC client** (`cmd/gui-gio/service.go`) must have **zero GUI imports**.
  It only imports `internal/scan`, `encoding/json`, `net`, and stdlib. This makes it
  reusable from the TUI, future frontends, and tests without pulling in Gio.
- **All display logic** (layouts, colours, font sizes, widget state) lives in the
  front-end package only. No display constants or widget references in `internal/`.
- When adding a feature: implement in `internal/scan/` first, expose via `ServiceCmd`/`ServiceMsg` if it needs elevation or background capture, then wire into the front-end last.

### Legacy Win32 GUI (`cmd/gui-win/`) — deprecated

- This package is **frozen**. Do not add features. It exists for reference and
  regression comparison during the Gio migration.
- `runtime.LockOSThread()` is called inside `guiwin.Run()` before any Win32
  call. Do not move or remove it.
- `runtime.LockOSThread()` is called inside `guiwin.Run()` before any Win32
  call. Do not move or remove it.
- **Framework vs application split** — `cmd/gui-win/` is divided into framework
  files and application files:
  - `fw_win32.go` — all Win32 types, constants, DLL proc references, and
    thin Go wrappers. Zero NetScope application logic here. The goal is that `fw_*.go` files
    could be extracted into a standalone module in the future with no changes
    to their contents.
  - `fw_dialog.go` — modal loop (`runModal`/`closeModal`), `registerDialogClass`
    helper, and `ctlColorDialog` WM_CTLCOLORSTATIC handler.
  - `win32.go` — **application** constants only: custom WM_APP message IDs,
    control IDs (`IDC_*`), menu command IDs (`IDM_*`), and `isElevated()`.
  - All other files (`ui.go`, `dialog.go`, `dialog_host.go`, `listview.go`,
    `main.go`, `service.go`, `crash.go`, `icon.go`) are application code.
  - **Rule:** do not add application constants or logic to `fw_*.go` files.
    Do not add Win32 plumbing (proc vars, wrappers, structs) to application files.
- **Before adding or fixing any GUI behaviour, ask: can this be a framework helper?**
  If the same Win32 pattern will appear in more than one place (colour handling,
  control layout, font application, message routing, etc.), add it to `fw_win32.go`
  or `fw_dialog.go` first and consume it from there. Standardise and deduplicate
  rather than copy-pasting into individual dialogs or WndProcs.
- The modal dialog pattern uses `runModal` / `closeModal` in `fw_dialog.go`.
  `enableWindow(parent, true)` must be called **before** `destroyWindow` to
  avoid focus going to the desktop.
- To register a new dialog window class, call `registerDialogClass(name, wndProc)`
  at the top of the `showXxxDialog` function — no `sync.Once` boilerplate needed.
- For `WM_CTLCOLORSTATIC` in dialog WndProcs, return `ctlColorDialog(wParam)`.
- The FAQ dialog uses `WS_EX_TOPMOST` + a self-contained message pump instead
  of disabling the parent window.
- The `.syso` resource file (`resource_windows_amd64.syso`) is generated by
  `cmd/gen-rsrc/` reading `cmd/gui-win/versioninfo.json`. Do not hand-edit
  the `.syso`.

### Module / dependencies

- No network access during CI. All dependencies must already be in the module
  cache or vendor directory.
- If `golang.org/x/sync` is missing, add a `replace` directive pinning it to
  `v0.10.0` as a workaround until `go mod tidy` can run with network access.
- Use `GONOSUMDB='*'` when running `go mod tidy` in an air-gapped environment.

---

## Architectural Boundaries

Keep a strict separation between layers. When in doubt, put logic in the lowest appropriate layer:

| Layer | Location | Responsibility |
| --- | --- | --- |
| **Backend** | `internal/scan/` | All network I/O, scanning, enrichment, result types, wire protocol types (`ServiceCmd`/`ServiceMsg`) |
| **Service IPC client** | `cmd/gui-gio/service.go` | Platform-agnostic subprocess spawn + JSON-over-TCP channel; **no Gio/Win32 imports** — reusable by any front-end |
| **Config** | `internal/config/` | Serialisation, defaults, path resolution, `ToScanConfig()` conversion |
| **Front-end (Gio)** | `cmd/gui-gio/` | Gio layout, widgets, event loop — Windows + Linux |
| **Front-end (Win32, legacy)** | `cmd/gui-win/` | Frozen Win32 GUI — no new features |
| **Front-end (TUI)** | `cmd/net-scope/tui_notwindows.go` + `cmd/tui/` | Bubbletea TUI — Linux/BSD |
| **Front-end (CLI)** | `cmd/net-scope/cli.go` + `cmd/cli/` | Plain text output — all platforms |

**Rules:**

- Do not add scanning, enrichment, or capture logic to any GUI or CLI file.
- Do not add Win32 or platform-specific code outside `cmd/gui-win/`.
- Do not add Gio imports outside `cmd/gui-gio/` UI files — the service IPC client in `cmd/gui-gio/service.go` must remain GUI-framework-free.
- The service IPC client is shared infrastructure — treat it like a library, not a GUI component. Any front-end (Gio, TUI, future Linux CLI) can import and use it.
- Config parsing and defaults live in `internal/config/`; frontends only call `Load()` / `SaveTo()`.
- `internal/scan/` is the single source of truth for all wire protocol types. Never duplicate `ServiceCmd`/`ServiceMsg`/`Result` in a front-end package.

---
