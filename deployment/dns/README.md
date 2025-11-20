## Route 53 Alias Updates

The `*-alias.json` files in this directory contain `change-resource-record-sets`
payloads for the public endpoints (api/ui/grpc/auth) pointing to the current ALBs.
Apply them with:

```bash
./deployment/dns/update-aliases.sh <hosted-zone-id>
```

You can optionally pass specific JSON files as additional arguments to update only
certain records.
