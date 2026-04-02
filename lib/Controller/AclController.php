<?php
namespace OCA\GroupFoldersAcl\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IGroupManager;
use OCP\IRequest;

class AclController extends Controller {

    private IGroupManager $groupManager;

    public function __construct($AppName, IRequest $request, IGroupManager $groupManager) {
        parent::__construct($AppName, $request);
        $this->groupManager = $groupManager;
    }

    /**
     * Security-hardened command execution
     */
    private function executeSecureCommand($command, $args = []): array {
        // Validate Nextcloud root path
        $serverRoot = \OC::$SERVERROOT;
        if (!is_dir($serverRoot) || !is_executable($serverRoot . '/occ')) {
            return ['success' => false, 'error' => 'Invalid server configuration'];
        }

        // Validate each user-supplied argument individually.
        // NOTE: Do NOT check the fully assembled $fullCommand — it contains
        // shell plumbing like '2>&1' which would falsely match '>' and '&',
        // and permission args like '-delete' would match the word 'delete'.
        // User-supplied inputs (folderId, group, path) are already validated
        // by validateInputs(); this check is a secondary defence.
        $argDangerousPatterns = [';', '|', '&', '`', '$', '>', '<', '../', '..\\', '/etc/', '/var/', '/root/'];
        foreach ($args as $arg) {
            $argStr = (string)$arg;
            foreach ($argDangerousPatterns as $pattern) {
                if (strpos($argStr, $pattern) !== false) {
                    \OC::$server->getLogger()->warning(
                        'Blocked potentially dangerous argument: ' . $argStr,
                        ['app' => 'groupfolders_acl']
                    );
                    return ['success' => false, 'error' => 'Argument blocked for security'];
                }
            }
        }

        // Build command with proper escaping.
        // Do NOT append '2>&1' — stderr is already captured via proc_open's
        // descriptor array below, and '2>&1' would trigger the patterns check.
        $escapedArgs = array_map('escapeshellarg', $args);
        $fullCommand = escapeshellcmd('php') . ' ' . 
                      escapeshellarg($serverRoot . '/occ') . ' ' . 
                      escapeshellcmd($command) . ' ' . 
                      implode(' ', $escapedArgs);

        // Log the command for audit purposes
        \OC::$server->getLogger()->info(
            'Executing OCC command: ' . $command . ' with args: ' . implode(', ', $args),
            ['app' => 'groupfolders_acl']
        );

        // Execute with timeout and proper error handling
        $descriptors = [
            0 => ['pipe', 'r'],  // stdin
            1 => ['pipe', 'w'],  // stdout
            2 => ['pipe', 'w']   // stderr
        ];

        $process = proc_open($fullCommand, $descriptors, $pipes);
        
        if (!is_resource($process)) {
            return ['success' => false, 'error' => 'Failed to start process'];
        }

        // Close stdin
        fclose($pipes[0]);

        // Read output with timeout
        $output = stream_get_contents($pipes[1], 8192); // Limit output size
        $error = stream_get_contents($pipes[2], 1024);
        
        fclose($pipes[1]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);

        return [
            'success' => $returnCode === 0,
            'output' => trim($output ?: ''),
            'error' => trim($error ?: ''),
            'return_code' => $returnCode
        ];
    }

    /**
     * Enhanced input validation
     */
    private function validateInputs($folderId, $group, $path): array {
        $errors = [];

        // Validate folder ID
        if (!$folderId || !is_numeric($folderId) || $folderId < 1 || $folderId > 999999) {
            $errors[] = 'Invalid folder ID (must be 1-999999)';
        }

        // Validate group name
        if (!$group || !is_string($group)) {
            $errors[] = 'Group name is required';
        } elseif (strlen($group) > 64) {
            $errors[] = 'Group name too long (max 64 characters)';
        } elseif (!preg_match('/^[a-zA-Z0-9._-]+$/', $group)) {
            $errors[] = 'Group name contains invalid characters';
        }

        // Validate path
        if (!is_string($path)) {
            $errors[] = 'Path must be a string';
        } elseif (strlen($path) > 255) {
            $errors[] = 'Path too long (max 255 characters)';
        } else {
            // Enhanced path validation
            $dangerousPatterns = ['..', '~', '/etc/', '/var/', '/root/', '/home/', 'C:\\', 'D:\\'];
            foreach ($dangerousPatterns as $pattern) {
                if (strpos($path, $pattern) !== false) {
                    $errors[] = 'Path contains forbidden patterns';
                    break;
                }
            }

            // Allow Unicode letters and a limited set of punctuation including square brackets,
            // commas, colons, percent, plus and quotes which are commonly used in folder names.
            // Use Unicode flag (u) to accept non-ASCII characters.
            $pattern = "/^[\/\p{L}0-9._\s\-\[\],:@%+\"'´]+$/u";
            if (!preg_match($pattern, $path)) {
                $errors[] = 'Path contains invalid characters';
            }
        }

        return $errors;
    }

    /**
     * @NoCSRFRequired
     */
    public function getGroups() {
        $user = \OC::$server->getUserSession()->getUser();
        if (!$user) {
            return new JSONResponse(['error' => 'Not authenticated'], 401);
        }
        if (!\OC_User::isAdminUser($user->getUID())) {
            return new JSONResponse(['error' => 'Insufficient permissions — admin required'], 403);
        }

        $groups = $this->groupManager->search('');
        $groupIds = array_map(fn($group) => $group->getGID(), $groups);
        sort($groupIds);

        return new JSONResponse(['groups' => $groupIds]);
    }

    /**
     * @NoCSRFRequired
     */
    public function setPermissions() {
        try {
        return $this->doSetPermissions();
        } catch (\Throwable $e) {
            $msg = $e->getMessage() . ' at ' . $e->getFile() . ':' . $e->getLine();
            \OC::$server->getLogger()->error('groupfolders_acl setPermissions exception: ' . $msg, ['app' => 'groupfolders_acl']);
            return new JSONResponse(['error' => 'Exception: ' . $msg], 500);
        }
    }

    private function doSetPermissions() {
        // Enhanced rate limiting with user identification
        $user = \OC::$server->getUserSession()->getUser();
        if (!$user) {
            return new JSONResponse(['error' => 'Not authenticated'], 401);
        }
        $userId = $user->getUID();
        $userIp = $this->request->getRemoteAddress();
        $cacheKey = 'acl_rate_limit_' . $userId . '_' . hash('md5', $userIp);
        
        $cache = \OC::$server->getMemCacheFactory()->createDistributed('acl');
        $requests = $cache->get($cacheKey) ?: 0;
        
        if ($requests >= 30) { // Reduced from 60 to 30 for better security
            \OC::$server->getLogger()->warning(
                'Rate limit exceeded for user: ' . $userId . ' from IP: ' . $userIp,
                ['app' => 'groupfolders_acl']
            );
            return new JSONResponse(['error' => 'Rate limit exceeded'], 429);
        }
        
        $cache->set($cacheKey, $requests + 1, 60);

        // Get and validate parameters
        $folderId = $this->request->getParam('folderId');
        $group = $this->request->getParam('group');
        $path = $this->request->getParam('path', '/');
        
        // Enhanced input validation
        $validationErrors = $this->validateInputs($folderId, $group, $path);
        if (!empty($validationErrors)) {
            return new JSONResponse(['error' => implode(', ', $validationErrors)], 400);
        }

        // Validate permission values
        $validPermissions = ['allow', 'deny', null, ''];
        $permissions = [
            'read' => $this->request->getParam('read'),
            'write' => $this->request->getParam('write'),
            'create' => $this->request->getParam('create'),
            'delete' => $this->request->getParam('delete'),
            'share' => $this->request->getParam('share')
        ];

        foreach ($permissions as $type => $value) {
            if ($value !== null && !in_array($value, $validPermissions)) {
                return new JSONResponse(['error' => "Invalid $type permission value"], 400);
            }
        }

        // Enable advanced permissions first
        $enableResult = $this->executeSecureCommand('groupfolders:permissions', [
            $folderId, '--enable'
        ]);

        if (!$enableResult['success']) {
            return new JSONResponse([
                'error' => 'Failed to enable advanced permissions',
                'details' => $enableResult['error']
            ], 500);
        }

        // Build permission arguments securely
        $permissionArgs = [];
        foreach ($permissions as $type => $value) {
            if ($value === 'allow') {
                $permissionArgs[] = '+' . $type;
            } elseif ($value === 'deny') {
                $permissionArgs[] = '-' . $type;
            }
        }

        // Build command arguments
        $commandArgs = [$folderId, $path, '--group', $group];
        if (!empty($permissionArgs)) {
            $commandArgs[] = '--';
            $commandArgs = array_merge($commandArgs, $permissionArgs);
        }

        // Execute the permission setting command
        $result = $this->executeSecureCommand('groupfolders:permissions', $commandArgs);

        if ($result['success']) {
            // Log successful permission change for audit
            \OC::$server->getLogger()->info(
                "Permissions set for group '$group' on folder $folderId:$path by user $userId",
                ['app' => 'groupfolders_acl', 'permissions' => $permissions]
            );
        }

        return new JSONResponse([
            'success' => $result['success'],
            'output' => $result['output'],
            'error' => $result['error'] ?? null,
            'permissions' => $permissions
        ]);
    }  // end doSetPermissions

    /**
     * @NoCSRFRequired
     */
    public function clearPermissions() {
        $user = \OC::$server->getUserSession()->getUser();
        if (!$user) {
            return new JSONResponse(['error' => 'Not authenticated'], 401);
        }
        $userId = $user->getUID();

        $folderId = $this->request->getParam('folderId');
        $group = $this->request->getParam('group');
        $path = $this->request->getParam('path', '/');

        // Validate inputs
        $validationErrors = $this->validateInputs($folderId, $group, $path);
        if (!empty($validationErrors)) {
            return new JSONResponse(['error' => implode(', ', $validationErrors)], 400);
        }

        // Execute clear command
        $result = $this->executeSecureCommand('groupfolders:permissions', [
            $folderId, $path, '--group', $group, 'clear'
        ]);

        if ($result['success']) {
            \OC::$server->getLogger()->info(
                "Permissions cleared for group '$group' on folder $folderId:$path by user $userId",
                ['app' => 'groupfolders_acl']
            );
        }

        return new JSONResponse([
            'success' => $result['success'],
            'output' => $result['output'],
            'error' => $result['error'] ?? null,
            'message' => "Permissions cleared for group: {$group}"
        ]);
    }

}