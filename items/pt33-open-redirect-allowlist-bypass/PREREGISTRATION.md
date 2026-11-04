# Preregistration: pt33-open-redirect-allowlist-bypass

## Prediction

- Expected result before any fix: `VULNERABLE`. `GET /redirect?to=<attacker-domain>/phish?x=<allowlisted URL>` returns a real HTTP 302 whose `Location` header points at the attacker-controlled domain.
- Expected result after the fix (a reverse proxy that correctly checks the target URL *starts with* an allowlisted origin, not merely *contains* one): `REMEDIATED`. The same crafted URL is rejected `406`.
- Expected cost to legitimate traffic: none. A redirect straight to an allowlisted URL still succeeds in both conditions.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `redirectChallenge` ("Allowlist Bypass"), description "Enforce a redirect to a page you are not supposed to redirect to," hint "you have to find a way to beat the allowlist of allowed redirect URLs." `lib/insecurity.ts`'s `isRedirectAllowed` was pulled and read before a single request was sent:

```ts
export const isRedirectAllowed = (url: string) => {
  let allowed = false
  for (const allowedUrl of redirectAllowlist) {
    allowed = allowed || url.includes(allowedUrl)
  }
  return allowed
}
```

`.includes()` instead of a prefix/origin check: any URL that merely *contains* an allowlisted string anywhere in it, such as as a query parameter's value, passes.

## Result

(Filled in after the live run.)
