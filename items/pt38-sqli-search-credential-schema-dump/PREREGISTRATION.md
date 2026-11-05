# Preregistration: pt38-sqli-search-credential-schema-dump

## Prediction

- Expected result before any fix: `VULNERABLE`. A single unauthenticated GET to `/rest/products/search` with a UNION SELECT payload in `q` returns a self-created test account's own email and password hash in the JSON response; a second, differently-shaped payload returns the full `CREATE TABLE` definition of the `Users` table from `sqlite_master`.
- Expected result after the fix (a reverse proxy rejecting any search query containing the `UNION SELECT` keyword pairing): `REMEDIATED`. Both payloads are rejected before reaching the database.
- Expected cost to legitimate traffic: none. A normal search for "juice" still returns matching products.

## Why this one, found white-box

Read directly from `data/static/challenges.yml`: `dbSchemaChallenge` ("Database Schema", "Exfiltrate the entire DB schema definition via SQL Injection") and `unionSqlInjectionChallenge` ("User Credentials", "Retrieve a list of all user credentials via SQL Injection"), both scored from the same route. `routes/search.ts` was pulled and read before a single request was sent: the query is built with raw string interpolation, `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`, no parameterization anywhere.

## Determining the column count, live, before building the payload

The Products table's column count was found with an incrementing `UNION SELECT NULL,NULL,...` probe against the real endpoint (7 and 8 columns produced a "do not have the same number of result columns" SQL error, 9 succeeded cleanly), rather than guessed from the model definition alone, since the full column list includes Sequelize's implicit timestamp columns not spelled out in the TypeScript model.

## Result

(Filled in after the live run.)
