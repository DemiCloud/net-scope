# NetScope — Agent / Contributor Instructions

## Collaboration Philosophy

Development is a collaborative process. Agents are expected to exercise independent technical judgment, not passive agreement. When a different solution better aligns with industry standards or formal specifications (e.g., RFCs, ISO, IEEE), agents should raise concerns and advocate for the more appropriate approach.

## Project Overview

NetScope (binary: `net-scope`) is a network inspection and reconnaissance tool combining
active probing, passive signal analysis, and change detection for LAN environments.
Written in Go 1.25.
It produces a **single binary per platform** from `cmd/net-scope/`.
The binary exposes all modes as subcommands:

```text
net-scope cli    [target] [flags]   # plain-text output — all platforms
net-scope tui    [target] [flags]   # Bubbletea TUI — Linux/BSD only
net-scope gui    [target]           # native GUI — Windows (Win32) or Linux GUI build
net-scope service <addr> <token>    # internal: sensor service subprocess
```

When run with **no subcommand**, the platform default is used unless
`default_mode` is set in `config.toml`:

| Platform | Default mode | Notes |
| --- | --- | --- |
| Windows (terminal) | `cli` | `AttachConsole` succeeds |
| Windows (double-click) | `gui` | No parent console |
| Linux (static build) | `cli` | Override via `default_mode = "tui"` in config; no GUI in static binary |
| Linux (GUI build) | `cli` | Override via `default_mode = "gui"` or `"tui"` in config |
| FreeBSD / BSD | `cli` | GUI subcommand not available; TUI is the interactive interface |

The old `cmd/cli/` and `cmd/tui/` entry points still exist and are buildable
in isolation, but **the canonical entry point is `cmd/net-scope/`**.

`cmd/gui-win/` is the **primary Windows GUI** — native Win32 controls, no CGo,
no framework dependencies. This is the active development path.

`cmd/gui-gtk/` is the **optional Linux GUI** — GTK3, CGo required, dynamically
linked. Only included when built with the `gui` build tag (`make linux-gui`).
The standard static Linux binary does not include the GUI subcommand.

---

## Repository Layout

```text
cmd/
  net-scope/          ← unified entry point (build this)
    main.go           ← InitVendorDB + calls run()
    cli.go            ← runCLI() — all platforms
    tui_notwindows.go ← runTUI() — Linux/BSD only (!windows build tag)
    dispatch_windows.go  ← subcommand dispatch; AttachConsole heuristic for default
    dispatch_linux_gui.go   ← subcommand dispatch for Linux GUI build (linux,gui tag)
    dispatch_other.go       ← subcommand dispatch; CLI default for Linux static + BSD
  gui-win/            ← package guiwin — Win32 GUI (Windows only, primary graphical target)
    fw_win32.go       ← Win32 types, constants, DLL procs, thin wrappers (no app logic)
    fw_dialog.go      ← modal loop, registerDialogClass, ctlColorDialog helper
    fw_listview.go    ← ListView helpers
    win32.go          ← app constants: WM_APP IDs, IDC_*, IDM_*, isElevated()
    main.go           ← Run(version, target string); LockOSThread
    ui.go             ← main window WndProc, layout, menus
    service.go        ← sensor service IPC client (no Win32 imports; reusable)
    (other app files: dialog.go, dialog_host.go, listview.go, crash.go, icon.go)
  gui-gtk/            ← package guigtk — GTK3 GUI (Linux only, build tag: linux,gui)
    main.go           ← Run(version, target string)
    ui.go             ← GTK window, widgets, event loop
    (service.go is shared from cmd/gui-win/service.go logic — or duplicated minimally)
  gen-ico/            ← go run ./cmd/gen-ico/ → cmd/gui-win/icon.ico
  gen-rsrc/           ← go run ./cmd/gen-rsrc/ → cmd/gui-win/resource_windows_amd64.syso
  cli/                ← standalone CLI (legacy, keep for reference)
  tui/                ← standalone TUI (legacy, keep for reference)
internal/
  config/             ← TOML config; Load() never auto-writes on first run
  scan/               ← active scanning library: probing, discovery, wire types (ServiceCmd/ServiceMsg)
  netinfo/            ← OS system queries: interfaces, ARP/DNS/route tables, sockets, hosts file,
                         DHCP capture, elevation check, private-network utility
```

---

## Build Commands

```bash
# Dev builds
make linux           # → build/net-scope_linux_amd64        (static; CLI + TUI only)
make linux-gui       # → build/net-scope_linux_amd64_gui     (CGo + GTK3; CLI + TUI + GUI)
make windows         # → build/net-scope_windows_amd64.exe   (runs gen-resources first)
make bsd             # → build/net-scope_freebsd_amd64       (static; CLI + TUI only)

# Regenerate icon.ico + resource_windows_amd64.syso (called automatically by make windows)
make gen-resources

# Stripped release builds → dist/ + checksums.txt
make release

# Tests / vet
make test
make vet
```

Windows cross-compilation is done from Linux (WSL Fedora). Linux and BSD can also be
cross-compiled from Linux. The Linux GUI build must be done natively on Linux.

| Target | CGo | Notes |
| --- | --- | --- |
| Windows (amd64) | **None** — `CGO_ENABLED=0` | Win32 via `syscall.NewLazyDLL`; no framework deps |
| Linux static (amd64) | **None** — `CGO_ENABLED=0` | CLI + TUI only; fully static binary |
| Linux GUI (amd64) | **Required** — `gcc` + `libgtk-3-dev libglib2.0-dev` | GTK3; dynamically linked; desktop use |
| FreeBSD (amd64) | **None** — `CGO_ENABLED=0` | CLI + TUI only; no GUI |

The "no CGo" rule applies to **Windows, Linux static, and FreeBSD targets**.
CGo is required for the Linux GUI build only.

---

## Git Workflow

**After every meaningful change, make a commit.** This applies to:

- Bug fixes (including single-line corrections)
- New features or behaviour changes
- Refactors or code reorganisation
- Documentation / AGENTS.md updates
- Build / Makefile changes

**Before committing, run the test suite and confirm it passes:**

```bash
wsl -d Fedora -- bash -c "cd /home/user/dev/net-scope && go test ./..."
```

Do not commit if any test fails. If a change intentionally removes functionality, update
or delete the affected tests in the same commit. If you add new logic, add corresponding
tests before committing.

Commit commands (run inside the Fedora WSL environment):

```bash
wsl -d Fedora -- bash -c "cd /home/user/dev/net-scope && git add <files> && git commit -m '<message>'"
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

**Never commit compiled binaries.** Only source files, generated Go resources
(`.syso`, embedded byte slices), and checked-in data files (e.g. `oui.json`) belong
in the repository. Compiled binaries must live in gitignored directories (`build/`,
`dist/`) produced by `make`. Before every commit, verify the staged file list does
not contain any ELF/PE/Mach-O executables:

```bash
# Review staged files and spot-check any suspiciously large or binary-named entries:
git diff --cached --name-only
# Confirm no binary is staged (should exit 0 with no output):
git diff --cached --name-only | xargs -r file | grep -i "ELF\|PE32\|Mach-O" && echo "ERROR: binary staged" || true
```

If a binary is accidentally staged, remove it before committing:

```bash
git rm --cached <binary-file>
```

Binaries compiled at the **repo root** are also covered by `.gitignore` patterns
(`/net-scope`, `/net-scope_*`). **Never run `go build` without an explicit `-o`
flag that targets `build/` or `dist/`** — a bare `go build ./cmd/net-scope/`
drops the binary in the working directory where it can be accidentally staged.

**Keep the wiki up to date.** The wiki lives in `.wiki/` (a separate git repo, cloned locally). When a change affects user-visible behaviour documented there, update the relevant `.wiki/*.md` file in the same working session. If `.wiki/` is missing or empty, notify the operator — the wiki repo needs to be cloned first: `git clone https://github.com/demicloud/net-scope.wiki.git .wiki`

---

## Key Conventions

### Go

- **No CGo on Windows, Linux static, or FreeBSD targets.** The Win32 GUI uses `syscall.NewLazyDLL` exclusively. CGo is required only for the Linux GTK GUI build.
- All `cmd/gui-win/` files carry `//go:build windows` and `package guiwin`.
  Never change the package back to `main`.
- All `cmd/gui-gtk/` files carry `//go:build linux && gui` and `package guigtk`.
- Version is injected at link time: `-ldflags "-X main.version=<tag>"`.
  The variable lives in `cmd/net-scope/main.go` as `var version = "dev"`.
- `config.Load()` returns defaults silently when no file exists — it does
  **not** write a starter file. The GUI prompts on first save.

### GUI (all front-ends)

- **All network I/O goes through the sensor service subprocess — on every platform.**
  No GUI package (Win32 or GTK) may call scan functions, open sockets, or
  perform probing directly. The service IPC channel is the only allowed path.
  If a new feature touches the network, it belongs in `internal/scan/` and is
  invoked via `scan.ServiceCmd` / `scan.ServiceMsg`, not from a UI event handler.
- **The service IPC client** (`cmd/gui-win/service.go`) must have **zero GUI imports**.
  It only imports `internal/scan`, `encoding/json`, `net`, and stdlib. This makes it
  reusable from the GTK front-end, the TUI, and tests.
- **All display logic** (layouts, colours, font sizes, widget state) lives in the
  front-end package only. No display constants or widget references in `internal/`.
- When adding a feature: implement in `internal/scan/` first, expose via `ServiceCmd`/`ServiceMsg` if it needs elevation or background capture, then wire into the front-end last.

### Win32 GUI (`cmd/gui-win/`) — primary Windows graphical target

- This package is the **active Windows GUI**. New Windows GUI features go here.
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
- **Use existing framework interfaces — never reimplement them.** Before writing
  raw Win32 calls (e.g. `LVITEM` / `LVM_INSERTITEM` / `setSubItem` sequences,
  `LVM_SETITEM`, `LVM_HITTEST`, etc.) check whether a helper already exists in
  `fw_listview.go` or `fw_win32.go` that covers the pattern. Examples:
  `listViewAppendRow`, `listViewGetCellText`, `listViewGetSelectedRows`,
  `listViewAddColumn`, `subclassListViewManaged`, `setSubItem`, `lvTextSort`,
  `runModal` / `closeModal`, `registerDialogClass`, `ctlColorDialog`.
  If a helper is missing but the pattern appears in more than one place, add it
  to the appropriate `fw_*.go` file and use it from both sites.
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
- **UI state persistence** — `internal/config/state.go` defines `State`,
  `WindowState`, `TabColumnState`, `ColumnState`, and `SortState`. When making
  a UI change, check whether state persistence needs updating:
  - **New tab / view** — add a constant to `tabIndexToView` in `win32.go` and a
    matching entry in the snapshot/restore functions in `listview.go`.
  - **New column on an existing tab** — add its stable key to the appropriate
    `*ColKeys` slice in `listview.go`. Keys are persisted; never rename them.
  - **Renamed or reordered column** — update the `*ColKeys` entry to match; the
    key must stay the same even if the display title changes.
  - **New per-window/session field** (e.g. sidebar width) — add a field to
    `State` or a sub-struct; give it a `json:",omitempty"` tag so old files
    without the field decode cleanly.
  - Do **not** bump `stateVersion` until after release 1.0. The loader silently
    falls back to `DefaultState()` on version mismatch, so bumping it discards
    every user's saved state.

### Linux GTK GUI (`cmd/gui-gtk/`) — optional Linux graphical target

- Build tag: `//go:build linux && gui`. Only compiled when `make linux-gui` is run.
- Uses GTK3 via `gotk3`. CGo required. Dynamically linked against system GTK libraries.
- The static Linux binary (`make linux`) does NOT include this package.
- The `gui` subcommand in the static build prints "not available in this build" and exits.
- GTK dev dependencies for building: `libgtk-3-dev libglib2.0-dev` (Debian/Ubuntu) or
  `gtk3-devel glib2-devel` (Fedora/RHEL).
- The service IPC client logic mirrors `cmd/gui-win/service.go` — same protocol, no
  GTK imports, only stdlib + `internal/scan`.

### Module / dependencies

- No network access during CI. All dependencies must already be in the module
  cache or vendor directory.
- If `golang.org/x/sync` is missing, add a `replace` directive pinning it to
  `v0.10.0` as a workaround until `go mod tidy` can run with network access.
- Use `GONOSUMDB='*'` when running `go mod tidy` in an air-gapped environment.
- Gio (`gioui.org`) has been removed from the project. Do not re-introduce it.

---

## Architectural Boundaries

Keep a strict separation between layers. When in doubt, put logic in the lowest appropriate layer:

| Layer | Location | Responsibility |
| --- | --- | --- |
| **Backend** | `internal/scan/` | All network I/O, scanning, enrichment, result types, wire protocol types (`ServiceCmd`/`ServiceMsg`) |
| **OS queries** | `internal/netinfo/` | Read-only OS system queries: interfaces, ARP/DNS/route tables, sockets, hosts file, DHCP capture, elevation check, private-network utility |
| **Service IPC client** | `cmd/gui-win/service.go` | Platform-agnostic subprocess spawn + JSON-over-TCP channel; **no Win32/GTK imports** — reusable by any front-end |
| **Config** | `internal/config/` | Serialisation, defaults, path resolution, `ToScanConfig()` conversion |
| **Front-end (Win32)** | `cmd/gui-win/` | Native Win32 GUI — Windows only; primary graphical target |
| **Front-end (GTK)** | `cmd/gui-gtk/` | GTK3 GUI — Linux only; optional GUI build (`linux,gui` tag) |
| **Front-end (TUI)** | `cmd/net-scope/tui_notwindows.go` + `cmd/tui/` | Bubbletea TUI — Linux/BSD; first-class interactive interface |
| **Front-end (CLI)** | `cmd/net-scope/cli.go` + `cmd/cli/` | Plain text output — all platforms |

**Rules:**

- Do not add scanning, enrichment, or capture logic to any GUI or CLI file.
- Do not add OS system queries or passive capture code to `internal/scan/` — put them in `internal/netinfo/`.
- Do not add Win32 platform-specific code outside `cmd/gui-win/`.
- Do not add GTK imports outside `cmd/gui-gtk/` UI files.
- The service IPC client is shared infrastructure — treat it like a library, not a GUI component. Any front-end (Win32, GTK, TUI) can import and use it.
- Config parsing and defaults live in `internal/config/`; frontends only call `Load()` / `SaveTo()`.
- `internal/scan/` is the single source of truth for all wire protocol types. Never duplicate `ServiceCmd`/`ServiceMsg`/`Result` in a front-end package.
- Do not introduce Gio, Fyne, Qt, or any other GUI framework. Win32 and GTK3 are the only permitted GUI backends.

---
