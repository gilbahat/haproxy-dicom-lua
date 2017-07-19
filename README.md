DICOM AAA lua module
====================

One key component to routing which is commonly present with multi-layered services is AAA (authentication, authorization and accounting)
when dealing with http, one would commonly be looking at things like client certificate, http authentication methods (basic, digest, others), host headers and sometimes IP-based access control.

When it comes to less common protocols like DICOM, these capabilities may not come out of the box for load balancers and proxy tiers. This lua module tries to fill the gap, as much as the framework will allow.

What is supported?

- Authenticate by called AE / calling AE
Calling and Called AE are extracted from the request and made available to authentication function

- Authenticate by DICOM provided identity
Provided authentication identity is extracted from the request and made available to the authenticating function.

One can add any other transaction variables such as source IP or ssl certificate DN into the authenticating function.

- Generating appropriate DICOM A-ASSOCIATE-REJ responses

a limitation of haproxy is that the actual code performing the authorization cannot be blocking, which limits to pre-loading the ruleset into memory and reloading haproxy to refresh it. 

- Sample fetches

You can fetch values from the A-ASSOCIATE-REQ and route accordingly

plans for a future release:
- sample file-based map implementation
- support IP mask comparisons
- support salted passwords (possibly problematic for latency)
- support DICOM health check (much of the code has been written, but haproxy does not support lua health checks yet)
