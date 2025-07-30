<?php
namespace OCA\GroupFoldersAcl\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;

class AclController extends Controller {

    public function __construct($AppName, IRequest $request) {
        parent::__construct($AppName, $request);
    }

    /**
     * @NoCSRFRequired
     */
    public function setPermissions() {
        // Rate limiting
        $userId = \OC::$server->getUserSession()->getUser()->getUID();
        $cacheKey = 'acl_rate_limit_' . $userId;
        $cache = \OC::$server->getMemCacheFactory()->createDistributed('acl');
        $requests = $cache->get($cacheKey) ?: 0;
        
        if ($requests >= 60) { // Max 60 requests per minute
            return new JSONResponse(['error' => 'Rate limit exceeded'], 429);
        }
        
        $cache->set($cacheKey, $requests + 1, 60);
        $folderId = $this->request->getParam('folderId');
        $group = $this->request->getParam('group');
        $path = $this->request->getParam('path', '/');
        
        // Input validation
        if (!$folderId || !is_numeric($folderId) || $folderId < 1) {
            return new JSONResponse(['error' => 'Invalid folder ID'], 400);
        }
        
        if (!$group || !is_string($group) || strlen($group) > 64) {
            return new JSONResponse(['error' => 'Invalid group name'], 400);
        }
        
        // Validate and sanitize path
        if (!is_string($path) || strlen($path) > 255) {
            return new JSONResponse(['error' => 'Invalid path'], 400);
        }
        
        // Block directory traversal
        if (strpos($path, '..') !== false || strpos($path, '~') !== false) {
            return new JSONResponse(['error' => 'Directory traversal not allowed'], 400);
        }
        
        // Advanced permissions: read, write, create, delete, share
        $read = $this->request->getParam('read');
        $write = $this->request->getParam('write');
        $create = $this->request->getParam('create');
        $delete = $this->request->getParam('delete');
        $share = $this->request->getParam('share');

        if (!$folderId || !$group) {
            return new JSONResponse(['error' => 'Missing folderId or group'], 400);
        }

        // Enable advanced permissions first
        $enableCmd = sprintf(
            'php %s/occ groupfolders:permissions %s --enable 2>&1',
            \OC::$SERVERROOT,
            escapeshellarg($folderId)
        );
        shell_exec($enableCmd);

        $permissions = [];
        if ($read === 'allow') $permissions[] = '+read';
        if ($read === 'deny') $permissions[] = '-read';
        if ($write === 'allow') $permissions[] = '+write';
        if ($write === 'deny') $permissions[] = '-write';
        if ($create === 'allow') $permissions[] = '+create';
        if ($create === 'deny') $permissions[] = '-create';
        if ($delete === 'allow') $permissions[] = '+delete';
        if ($delete === 'deny') $permissions[] = '-delete';
        if ($share === 'allow') $permissions[] = '+share';
        if ($share === 'deny') $permissions[] = '-share';

        $permStr = empty($permissions) ? '' : '-- ' . implode(' ', $permissions);

        $command = sprintf(
            'php %s/occ groupfolders:permissions %s %s --group %s %s 2>&1',
            \OC::$SERVERROOT,
            escapeshellarg($folderId),
            escapeshellarg($path),
            escapeshellarg($group),
            $permStr
        );

        $output = shell_exec($command);

        return new JSONResponse([
            'success' => $output !== null,
            'output' => trim($output ?: ''),
            'permissions' => compact('read', 'write', 'create', 'delete', 'share')
        ]);
    }

    /**
     * @NoCSRFRequired
     */
    public function clearPermissions() {
        // Rate limiting
        $userId = \OC::$server->getUserSession()->getUser()->getUID();
        $cacheKey = 'acl_rate_limit_' . $userId;
        $cache = \OC::$server->getMemCacheFactory()->createDistributed('acl');
        $requests = $cache->get($cacheKey) ?: 0;
        
        if ($requests >= 60) { // Max 60 requests per minute
            return new JSONResponse(['error' => 'Rate limit exceeded'], 429);
        }
        
        $cache->set($cacheKey, $requests + 1, 60);
        $folderId = $this->request->getParam('folderId');
        $group = $this->request->getParam('group');
        $path = $this->request->getParam('path', '/');

        // Input validation
        if (!$folderId || !is_numeric($folderId) || $folderId < 1) {
            return new JSONResponse(['error' => 'Invalid folder ID'], 400);
        }
        
        if (!$group || !is_string($group) || strlen($group) > 64) {
            return new JSONResponse(['error' => 'Invalid group name'], 400);
        }
        
        // Validate and sanitize path
        if (!is_string($path) || strlen($path) > 255) {
            return new JSONResponse(['error' => 'Invalid path'], 400);
        }
        
        // Block directory traversal
        if (strpos($path, '..') !== false || strpos($path, '~') !== false) {
            return new JSONResponse(['error' => 'Directory traversal not allowed'], 400);
        }

        if (!$folderId || !$group) {
            return new JSONResponse(['error' => 'Missing folderId or group'], 400);
        }

        // Clear all permissions for the group using clear as permission argument
        $command = sprintf(
            'php %s/occ groupfolders:permissions %s %s --group %s clear 2>&1',
            \OC::$SERVERROOT,
            escapeshellarg($folderId),
            escapeshellarg($path),
            escapeshellarg($group)
        );

        $output = shell_exec($command);

        return new JSONResponse([
            'success' => $output !== null,
            'output' => trim($output ?: ''),
            'message' => "Removed permissions for group: {$group}"
        ]);
    }

}