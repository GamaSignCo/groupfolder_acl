<?php
return [
    'routes' => [
        ['name' => 'acl#setPermissions', 'url' => '/api/set',    'verb' => 'POST'],
        ['name' => 'acl#clearPermissions','url' => '/api/clear',  'verb' => 'POST'],
    ]
];