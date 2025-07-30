# Group Folders ACL

A Nextcloud app that provides REST API for setting advanced ACL permissions on Group Folders subfolders.

## Features

- Set advanced permissions (read/write/create/delete/share) on Group Folders subfolders
- Admin-only access for security
- Simple REST API interface
- Supports allow/deny/inherit permission modes

## Installation

### Standard Installation
1. Copy the app to your Nextcloud apps directory
2. Enable the app: `occ app:enable groupfolders_acl`

### NethServer 8 Installation
1. Create app directory:
   ```bash
   mkdir -p /home/nextcloud1/.local/share/containers/storage/volumes/nextcloud-app-data/_data/custom_apps/groupfolders_acl/
   ```

2. Copy app files:
   ```bash
   cp -r groupfolders_acl/* /home/nextcloud1/.local/share/containers/storage/volumes/nextcloud-app-data/_data/custom_apps/groupfolders_acl/
   ```

3. Set ownership:
   ```bash
   chown -R 427761:427761 /home/nextcloud1/.local/share/containers/storage/volumes/nextcloud-app-data/_data/custom_apps/groupfolders_acl/
   ```

4. Enable the app:
   ```bash
   runagent -m nextcloud1 occ app:enable groupfolders_acl
   ```

**Note for NethServer 8:**
- Use `runagent -m nextcloud1` instead of direct `occ` commands
- App files go in `custom_apps/` directory within the container volume
- Check container user ID with: `ls -la /home/nextcloud1/.local/share/containers/storage/volumes/nextcloud-app-data/_data/`

## API Usage

### Set Permissions

```bash
POST /apps/groupfolders_acl/api/set
Content-Type: application/json

{
  "folderId": "1",
  "group": "finance",
  "path": "/2025/00043/Sales",
  "read": "allow",
  "write": "deny",
  "create": "deny",
  "delete": "deny",
  "share": "inherit"
}
```

### Clear Permissions

```bash
POST /apps/groupfolders_acl/api/clear
Content-Type: application/json

{
  "folderId": "1",
  "group": "finance",
  "path": "/2025/00043/Sales"
}
```

### Permission Values

- `"allow"` - Grant permission
- `"deny"` - Block permission  
- `null` or omitted - Inherit from parent (default)

### Response

```json
{
  "success": true,
  "output": "Permissions set successfully",
  "permissions": {
    "read": "allow",
    "write": "deny",
    "create": "deny", 
    "delete": "deny",
    "share": null
  }
}
```

## Requirements

- Nextcloud 25+
- Group Folders app enabled
- Admin privileges

## Security

- All endpoints require admin authentication
- Uses native Nextcloud occ commands
- Input validation and sanitization

## License

AGPL-3.0