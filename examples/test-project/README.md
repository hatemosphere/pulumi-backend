# Test Project

Mock Pulumi project for testing pulumi-backend. Uses the `random` provider — no cloud credentials needed.

## Full cycle

```bash
# 1. Start the backend
cd ../..
go build -o pulumi-backend ./cmd/pulumi-backend
./pulumi-backend &

# 2. Login
export PULUMI_ACCESS_TOKEN=test-token
pulumi login http://localhost:8080

# 3. Init stack
cd examples/test-project
pulumi stack init dev

# 4. Preview with diff
pulumi preview --diff

# 5. Apply
pulumi up -y

# 6. Change config and see diffs
pulumi config set petCount 4
pulumi config set prefix "prod"
pulumi preview --diff

# 7. Apply changes
pulumi up -y

# 8. Check state
pulumi stack export | jq '.deployment.resources | length'

# 9. Destroy
pulumi destroy -y
pulumi stack rm dev -y
```
