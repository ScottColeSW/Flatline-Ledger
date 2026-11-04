# Preregistration: pt27-yaml-bomb-dos

## Prediction

- Expected result before any fix: `VULNERABLE`. A plain legitimate GET to the product search endpoint, which normally answers in well under a second, takes an order of magnitude longer (predicted > 1.5s and > 3x its own unloaded baseline) while five billion-laughs YAML uploads are being parsed concurrently by the same server.
- Expected result after the fix (a reverse proxy throttling `.yml`/`.yaml` uploads to `POST /file-upload` by caller IP, 1 per 15-second window): `REMEDIATED`. Most of the five concurrent uploads are refused with HTTP 429 before ever reaching the backend parser, and the same legitimate request stays close to its unloaded baseline.
- Expected cost to legitimate traffic: none. A normal complaint upload that is not a `.yml`/`.yaml` file (a plain `.pdf`) is untouched by the control in either condition.

## A deliberate safety boundary

`routes/fileUpload.ts` itself carries a comment warning that XXE/XML-handling in this same file "regularly cause[s] 'segfault' crashes" in Docker/Heroku containers. Before building this item, the same 5-concurrent-bomb load used here was run once against the main `flatline-juice-shop` container and once against `flatline-juice-shop-unsafe` (started fresh for this item, per Scott's direction to keep anything DoS-shaped off the main container used by every other item) and both times the container recovered cleanly with no crash. This item intentionally stays at that same moderate intensity rather than escalating further, since the point is demonstrating the compensating control works, not finding the container's actual breaking point.

## Why this one, found black-box

The complaint page accepts a `.yml`/`.yaml` attachment with no login required. Uploading a classic nested anchor/alias "billion laughs" YAML took about 2 seconds and came back `503`, confirming a server-side timeout kicked in (and Juice Shop's own `yamlBombChallenge` flipped from this single request). That cap on one request's cost doesn't say anything about several at once: firing five of these uploads in parallel from one script measurably stalled an unrelated request on the same server, from ~0.17s to ~9.9s, a real, shared-resource denial of service.

## Corroboration against source

`routes/fileUpload.ts`'s `handleYamlUpload` parses the attachment with `yaml.load()` inside `vm.runInContext(..., { timeout: 2000 })`. The timeout bounds a single call; nothing in the handler, or anywhere else in the request path, limits how many such calls one caller can have in flight simultaneously. `data/static/challenges.yml` confirms `yamlBombChallenge` ("Memory Bomb", category "Insecure Deserialization") only requires triggering the single-request timeout once; it has no challenge at all for the concurrent-amplification angle that turns a capped per-request cost into real service degradation.

## Result

(Filled in after the live run.)
