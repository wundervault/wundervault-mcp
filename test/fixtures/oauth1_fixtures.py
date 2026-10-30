"""Independent OAuth 1.0a signatures for test/stamp-oauth1.test.ts (SPEC-oauth1, check 3).

Python's oauthlib signs each case; the TypeScript signer must agree. Regenerate with
    python3 -I test/fixtures/oauth1_fixtures.py > test/fixtures/oauth1.json
(oauthlib 3.2.2). The secrets below are published examples or made up for the test.
"""
import json
import sys
from urllib.parse import unquote

import oauthlib
from oauthlib.oauth1 import Client, SIGNATURE_HMAC_SHA1, SIGNATURE_HMAC_SHA256

FORM = 'application/x-www-form-urlencoded'
CASES = [
    # OAuth Core 1.0, Appendix A.5 (the photos.example.net example).
    dict(name='core10_appendix', method='GET', url='http://photos.example.net/photos?file=vacation.jpg&size=original',
         ck='dpf43f3p2l4k3l03', cs='kd94hf93k423kf44', tk='nnch734d00sl2jdk', ts_='pfkkdhi9sl3r4s00',
         nonce='kllo9940pd9333jh', timestamp='1191242096', alg='HMAC-SHA1', expect='tR3+Ty81lMeYAr/Fid0kMTYa/WM='),
    # X's "Creating a signature" example (a form-encoded POST with a query).
    dict(name='x_doc', method='POST', url='https://api.twitter.com/1.1/statuses/update.json?include_entities=true',
         body='status=Hello%20Ladies%20%2b%20Gentlemen%2c%20a%20signed%20OAuth%20request%21', ct=FORM,
         ck='xvz1evFS4wEEPTGEFPHBog', cs='kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw',
         tk='370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb', ts_='LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE',
         nonce='kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg', timestamp='1318622958', alg='HMAC-SHA1',
         expect='hCtSmYh+iHYCEqBWrE7C7hYmtUk='),
    # X API v2 post: a JSON body is not signed.
    dict(name='json_tweet', method='POST', url='https://api.x.com/2/tweets', body='{"text":"Trust your agent with the job, not the keys."}',
         ct='application/json', ck='ck-123', cs='cs+/=456~', tk='99-token', ts_='ts&secret*7',
         nonce='0123456789abcdef0123456789abcdef', timestamp='1761782400', alg='HMAC-SHA1'),
    # A query with a space as +, an encoded +, %20, ~ and *, a repeated name, non-ASCII, an empty value.
    dict(name='tricky_get', method='GET', url='https://api.example.com/1/search?q=a+b%2Bc%20d&q=~*&name=%C3%A9t%C3%A9&empty=',
         ck='key', cs='sec', tk='tok', ts_='tsec', nonce='n0nce', timestamp='1700000000', alg='HMAC-SHA1'),
    # NetSuite-style: HMAC-SHA256 with a realm, JSON body.
    dict(name='sha256_realm', method='POST', url='https://1234567-sb1.suitetalk.api.netsuite.com/services/rest/record/v1/customer?limit=5',
         body='{"companyName":"Acme"}', ct='application/json', realm='1234567_SB1',
         ck='consumer', cs='consumer-secret', tk='token', ts_='token-secret', nonce='abc123', timestamp='1700000001',
         alg='HMAC-SHA256'),
    # A port other than 443 is part of the signed address.
    dict(name='port_8443', method='GET', url='https://API.Example.com:8443/x?y=1',
         ck='key', cs='sec', tk='tok', ts_='tsec', nonce='n2', timestamp='1700000002', alg='HMAC-SHA1'),
    # A form body with +, a UTF-8 escape and an empty value.
    dict(name='form_body', method='POST', url='https://api.example.com/form', body='a=1+2&b=%E2%9C%93&c=', ct=FORM,
         ck='key', cs='sec', tk='tok', ts_='tsec', nonce='n3', timestamp='1700000003', alg='HMAC-SHA1'),
]

out = {'oauthlib': oauthlib.__version__, 'cases': []}
for c in CASES:
    client = Client(c['ck'], client_secret=c['cs'], resource_owner_key=c['tk'], resource_owner_secret=c['ts_'],
                    signature_method=SIGNATURE_HMAC_SHA1 if c['alg'] == 'HMAC-SHA1' else SIGNATURE_HMAC_SHA256,
                    nonce=c['nonce'], timestamp=c['timestamp'], realm=c.get('realm'))
    headers = {'Content-Type': c['ct']} if c.get('ct') else {}
    # A body that is not form-encoded is not part of an RFC 5849 signature. oauthlib would add
    # the oauth_body_hash extension for one, which we do not send (SPEC-oauth1, out of scope),
    # so it signs those requests without the body: the same signature RFC 5849 defines.
    body = c.get('body') if c.get('ct') == FORM else None
    _, signed, _ = client.sign(c['url'], http_method=c['method'], body=body, headers=headers)
    if 'oauth_body_hash' in signed['Authorization']:
        sys.exit(f"{c['name']}: oauthlib added a body hash")
    auth = signed['Authorization']
    sig = unquote(auth.split('oauth_signature="')[1].split('"')[0])
    if 'expect' in c and sig != c['expect']:
        sys.exit(f"{c['name']}: oauthlib gives {sig}, the published example says {c['expect']}")
    out['cases'].append({**{k: v for k, v in c.items() if k != 'expect'}, 'signature': sig, 'authorization': auth})
print(json.dumps(out, indent=2))
