# Security Specification (`prompts` Collection — Admin-Gated Writes)

## 1. Data Invariants
- Public guests (unauthenticated) may only `get` and `list` documents in `/prompts/{promptId}`.
- Only the verified administrator (`request.auth.token.email == 'kimju6391@gmail.com' && request.auth.token.email_verified == true`) may `create`, `update`, or `delete` documents in `/prompts/{promptId}`.
- Every document must contain **exact** keys: `['title', 'category', 'content', 'createdAt']` (no shadow fields).
- `createdAt` must equal `request.time` on `create` and must remain immutable (`incoming().createdAt == existing().createdAt`) on `update`.
- `update` may only modify `['title', 'category', 'content']`.
- `title`: `1..100` chars, `category`: `['사진 합성', '스타일 변환', '캐릭터·포스터']`, `content`: `1..10000` chars.

## 2. Adversarial Payloads Checked
1. **Unauthenticated Create/Update/Delete**: Denied by `isAdmin()`.
2. **Non-Admin Authenticated User**: Denied by `request.auth.token.email == 'kimju6391@gmail.com'`.
3. **Unverified Email Spoofing**: Denied by `request.auth.token.email_verified == true`.
4. **Shadow Field Injection**: Denied by `keys().hasOnly(...)` / `affectedKeys().hasOnly(...)`.
5. **Immutable `createdAt` Tampering on Update**: Denied by `incoming().createdAt == existing().createdAt`.
6. **Forged `createdAt` on Create**: Denied by `incoming().createdAt == request.time`.
7. **Invalid Category / Oversized Content / Empty Title**: Denied by `isValidPrompt()`.
8. **ID Poisoning**: Denied by `isValidId(promptId)`.
