# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

#### v0.1 foundation — implementation
- Cargo workspace: `remoter-core`, `remoter-vault`, `remoter-plugin-abi`,
  `remoter-plugin-sdk`, `remoter-ipc`, and the Tauri desktop application
- Design tokens extracted from the supplied screen designs, covering the dark,
  light and both high-contrast themes
- Local install script for Linux, and CI covering Rust, the frontend, security
  advisories and the plugin ABI licence boundary

#### Specification
- Project specification: architecture, threat model, vault format, data model,
  session pipeline, rendering, plugin system, storage
- Architecture Decision Records 0001–0012
- `LICENSE-EXCEPTION`: GPL-3.0 §7 additional permission allowing WebAssembly
  plugins to carry any licence
- Feature specifications: connections, protocols, tunnelling, import/export,
  recording and audit, internationalisation
- Interface specification: information architecture and design system
- Development documentation: setup, structure, standards, testing, release
- Roadmap through v1.0 and beyond
