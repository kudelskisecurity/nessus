nessus
======

Based on the Nessus REST API.

Real based on it, not so dsl, no nice object which will act by themself (I may
make one one day), every call that you make using the NessusLib object will
send a single request to Nessus.

If you are used to read the Nessus API, you will find it quite easy to use,
python objects map to resources (or subset of resources), nessus calls map to
REST API.

## install
It is using a standard `setup.py`, so you can use
```sh
easy_install .
```

## examples
If you want to use it, I recommend that you look into the test with the user
stories, but here is a simple example:

```python
from nessus import LibNessus


# create the nessus access
nessus = LibNessus(url, api_access_key, api_secret_key)

# get the available templates
templates = nessus.editor.list(NessusTemplateType.policy)
template = next(t for t in templates if t.name == 'discovery')

# create a policy with the choosen template
policy_id, _ = nessus.policies.create(template)
policy = next(p for p in nessus.policies.list() if p.id == policy_id)

# create a new scan
scan = nessus.scans.create(policy)

# launch the scan
scan_uuid = nessus.scans.launch(scan)

# wait until the scan is done (yup, ugly, but API calls, you know)
status = None
while status is not NessusScanStatus.completed:
    scans = nessus.scans.list()
    scanning = next(s for s in scans if s.uuid == scan_uuid)
    status = scanning.status
    sleep(1)

# get the scan details
scans = nessus.scans.list()
scanned = next(s for s in scans if s.uuid == scan_uuid)
details = nessus.scans.details(scanned)
```

## contact
If you need any features, more API calls, just drop a line on the bug tracker.

If any of test are failing, or you found a bug, provide a test case and write me
something (still on the bug tracker).
