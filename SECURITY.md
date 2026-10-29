# Security

Do not put credentials, private thread contents or infrastructure identifiers in public issues. Report suspected vulnerabilities privately at https://github.com/Midtown-Technology-Group/kadenco/security/advisories/new . Do not include sensitive data in public issues. Do not deploy this experimental candidate exposed directly to the Internet. Use operator-managed HTTPS/private connectivity, owner-only state permissions, allowlisted routes and scoped credentials.

Persistent diagnostic values and operational records are encrypted; host/timestamp/sequence indices and legacy audit metadata are plaintext. Keys must be provided separately. Diagnostics never record raw error text, tokens, response bodies or user messages. Logs can still reveal operational topology and must remain private. No secret scan can prove absence of every sensitive value.
