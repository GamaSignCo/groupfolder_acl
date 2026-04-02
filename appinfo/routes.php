<?php
return [
    'routes' => [
        ['name' => 'acl#getGroups',      'url' => '/api/groups', 'verb' => 'GET'],
        ['name' => 'acl#setPermissions', 'url' => '/api/set',    'verb' => 'POST'],
        ['name' => 'acl#clearPermissions','url' => '/api/clear',  'verb' => 'POST'],
    ]
];