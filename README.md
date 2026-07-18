# go-client-integration

Go client integration for Open Chat.

- Generated base REST client from backend API docs (`backend/server/swagger.json`)
- Handwritten `goclient.Client` wrapper for higher-level auth/session flows

Regenerate the base client from repository root:

```bash
python3 development/scripts/update_oc_go_client_base.py
```
