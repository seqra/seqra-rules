# Seqra Security Rules Collection

[![GitHub release](https://img.shields.io/github/release/seqra/seqra-rules.svg)](https://github.com/seqra/seqra-rules/releases)

A collection of security rules for [Seqra](https://github.com/seqra/seqra), a security-focused static analyzer for Java that combines the simplicity of pattern matching with the power of dataflow analysis. This repository aggregates high-quality security rules from multiple sources, including our own custom rules, to provide comprehensive coverage for Java security vulnerabilities.

## About Seqra

Seqra is a modern static analysis tool designed specifically for security auditing of Java applications. It offers:

- **Pattern-based rules with cross-module dataflow**: Simple, readable rule format interpreted with advanced taint tracking that follows dataflow across different project modules and even external dependencies
- **Advanced security detection**: Finds complex vulnerabilities that span multiple files, classes, and libraries — not just single-file pattern matches
- **Semgrep compatibility**: Compatible with Semgrep rule format
- **High performance**: Optimized for large codebases and CI/CD integration

## Rule selection

You can use rules selectively based on your needs:

- **semgrep-rules**: Open community rules from the Semgrep registry
- **gitlab-rules**: GitLab SAST rules
- **opengrep-rules**: Opengrep rules
- **seqra**: The most accurate and optimized rules for Seqra

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

- **Semgrep Open Rules**: Rules from the Semgrep registry under various open-source licenses
- **GitLab Rules**: Some rules are adapted from GitLab SAST analyzers under their respective licenses
- **Opengrep Rules**: Rules from the Opengrep community under various open-source licenses
- **Seqra Rules**: Original rules developed by the Seqra Team under MIT license

## Acknowledgments

- Semgrep community for maintaining high-quality security rules
- GitLab team for their comprehensive SAST rule collection
