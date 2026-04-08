# NetScope — Agent / Contributor Instructions

## Project Overview

NetScope (binary: `net-scope`) is a network inspection and reconnaissance tool combining
active probing, passive signal analysis, and change detection for LAN environments.
Written in Go 1.25.
It produces a **single binary per platform** from `cmd/net-sweep/`:

| Platform | Behaviour at launch |
|---|---|
| Windows (terminal) | `AttachConsole` succeeds → CLI mode |
| Windows (double-click) | No console → GUI mode (Win32, pure syscall) |
| Linux / BSD | `--tui` flag → Bubbletea TUI; otherwise CLI |

The old `cmd/cli/`, `cmd/tui/`, and `cmd/gui-win/` entry points still exist
and are buildable in isolation, but **the canonical entry point is
`cmd/net-sweep/`**.

---

## Repository Layout

```
cmd/
  net-sweep/          ← unified entry point (build this)
    main.go           ← InitVendorDB + calls run()
    cli.go            ← runCLI() — all platforms
    tui_notwindows.go ← runTUI() — Linux/BSD only (!windows build tag)
    dispatch_windows.go ← AttachConsole → CLI or guiwin.Run()
    dispatch_other.go   ← --tui flag routing
  gui-win/            ← package guiwin (NOT package main)
    main.go           ← Run(version, target string)
    win32.go          ← all syscall wrappers
    ui.go             ← main window + message loop
    dialog.go         ← settings, FAQ, version, config-location dialogs
    listview.go       ← custom listview helpers
    icon.go           ← programmatic radar-sweep icon
  gen-ico/            ← go run ./cmd/gen-ico/ → cmd/gui-win/icon.ico
  gen-rsrc/           ← go run ./cmd/gen-rsrc/ → cmd/gui-win/resource_windows_amd64.syso
  cli/                ← standalone CLI (legacy, keep for reference)
  tui/                ← standalone TUI (legacy, keep for reference)
internal/
  config/             ← TOML config; Load() never auto-writes on first run
  scan/              ← core scanner library
```

---

## Build Commands

```bash
# Dev builds
make linux           # → build/net-sweep_linux_amd64
make windows         # → build/net-sweep_windows_amd64.exe  (runs gen-resources first)
make bsd             # → build/net-sweep_freebsd_amd64

# Regenerate icon.ico + resource_windows_amd64.syso (called automatically by make windows)
make gen-resources

# Stripped release builds → dist/ + checksums.txt
make release

# Tests / vet
make test
make vet
```

Cross-compilation is done from Linux (WSL Fedora). No CGo; no external
toolchains required. `CGO_ENABLED=0` for Linux/BSD targets.

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
wsl -d Fedora -- bash -c "cd /home/user/dev/net-sweep && git add <files> && git commit -m '<message>'"
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
- **No CGo anywhere.** The Windows GUI uses `syscall.NewLazyDLL` exclusively.
- All `cmd/gui-win/` files carry `//go:build windows` and `package guiwin`.
  Never change the package back to `main`.
- Version is injected at link time: `-ldflags "-X main.version=<tag>"`.
  The variable lives in `cmd/net-sweep/main.go` as `var version = "dev"`.
- `config.Load()` returns defaults silently when no file exists — it does
  **not** write a starter file. The GUI prompts on first save.

### Windows GUI
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
| **Backend** | `internal/scan/` | All network I/O, scanning, enrichment, result types |
| **Service** | `cmd/gui-win/service.go` + OS service wrapper | Background capture (DHCP, passive listeners); should serve TUI and future Linux GUI too — not just the Windows GUI |
| **Config** | `internal/config/` | Serialisation, defaults, path resolution only |
| **Front-end** | `cmd/gui-win/`, `cmd/net-sweep/{cli,tui}*` | Display, user input, layout — **no business logic here** |

**Rules:**

- Do not add scanning, enrichment, or capture logic to any GUI or CLI file.
- Do not add Win32 or platform-specific code outside `cmd/gui-win/`.
- The service layer (sensor service / Windows service shim) should be reusable from the TUI and any future Linux GUI — it is not a GUI-only component.
- Config parsing and defaults live in `internal/config/`; frontends only call `Load()` / `SaveTo()`.

---

## Shelved Work (do not implement without discussion)

- Linux native GUI (toolkit not decided)
- Diff / snapshot system
- Filter language (`alive`, `open:22`, `vendor:X`)
- Debug menu (ARP/DNS inspect/clear)
- Broadcast tab auto-poll
- Admin mode toggle
