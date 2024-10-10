# GoWAF
A work in progress tool written in Go to check whether a list of domains/subs have a WAF in place when generic payloads are passed in params.

Is checked on the basis of a 403 forbidden error when sending the payload, but 200 without (signalling a WAF).
Also checks the SQL payload requests for 500 internal errors in case the param is vulnerable to sqli with further testing.

Plans include custom payload options, CLI support with flags, WAF provider detection (cloudflare, cloudfront, etc), and maybe open redirect integration.

