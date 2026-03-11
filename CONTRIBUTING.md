# Contributing to xmandate-sar-formatter

Thanks for your interest in contributing! This project implements the SAR v0.1 specification for AI agent task settlement attestation.

## Getting started

```bash
git clone https://github.com/xmandate-ai/xmandate-sar-formatter.git
cd xmandate-sar-formatter
npm install
npm run build
npm test
```

## Making changes

1. Fork the repo and create a branch from `main`.
2. Make your changes. Add or update tests as needed.
3. Ensure `npm run build && npm test` passes.
4. Open a pull request.

## What we're looking for

- Bug fixes and test coverage improvements
- Cross-implementation compatibility reports (especially against other SAR v0.1 implementations)
- Documentation improvements
- Edge runtime compatibility fixes

## Code style

- TypeScript strict mode
- No runtime dependencies beyond `@noble/ed25519`, `@noble/hashes`, and `canonicalize`
- Keep the bundle edge-compatible (no Node-only APIs in core paths)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
