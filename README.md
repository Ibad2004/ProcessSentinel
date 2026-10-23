# PC Security Assistant

A modular, read-only Windows process inspection and AI-assisted security analysis application.

## Current stage

This ZIP contains the initial project scaffold only. The process scanner, security analyzer,
Ollama integration, and desktop UI will be implemented and tested in later steps.

## Planned architecture

- `core/`: configuration and logging
- `scanner/`: read-only system inspection
- `security/`: evidence-based security checks
- `ai/`: local Ollama integration
- `ui/`: desktop interface
- `tests/`: automated tests
- `config/`: application settings

## Safety

The initial version is designed to be read-only. It will not terminate processes, delete files,
or change Windows settings.
