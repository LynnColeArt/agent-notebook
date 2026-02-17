<?php
declare(strict_types=1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Agent-Name, X-Agent-Token, X-Requested-With');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Simple .env loader for shared hosting where environment variables are not always set.
function load_environment_file(string $path): void
{
    if (!is_readable($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) {
        return;
    }

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || string_starts_with($trimmed, '#')) {
            continue;
        }
        $parts = explode('=', $trimmed, 2);
        if (count($parts) !== 2) {
            continue;
        }
        $key = trim($parts[0]);
        $value = trim($parts[1], "\"'\r\n\t ");
        if ($key !== '') {
            putenv("$key=$value");
        }
    }
}

function string_starts_with(string $haystack, string $needle): bool
{
    return $needle !== '' && strpos($haystack, $needle) === 0;
}

function string_contains(string $haystack, string $needle): bool
{
    return $needle !== '' && strpos($haystack, $needle) !== false;
}

function json_response(array $payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function fail(string $message, int $status = 400): void
{
    json_response(['success' => false, 'error' => $message], $status);
}

function get_header_value(array $headers, string $key): string
{
    foreach ($headers as $headerName => $value) {
        if (strcasecmp($headerName, $key) === 0) {
            return (string)$value;
        }
    }
    return '';
}

function get_request_path(): string
{
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($uri, PHP_URL_PATH);
    if (!is_string($path)) {
        return '/';
    }
    $path = rtrim($path, '/');
    if ($path === '') {
        return '/';
    }
    return $path;
}

function normalize_path(string $path): string
{
    $path = trim(str_replace('\\', '/', $path));
    $path = preg_replace('/\\s+/', ' ', $path);
    $path = trim($path, '/');
    if ($path === '') {
        return '';
    }
    if (string_contains($path, '..')) {
        throw new InvalidArgumentException('path cannot contain traversal');
    }

    $parts = array_filter(array_map('trim', explode('/', $path)), static fn($part) => $part !== '');
    $normalized = implode('/', $parts);
    if ($normalized === '') {
        return '';
    }
    return $normalized;
}

function get_headers_map(): array
{
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            return $headers;
        }
    }

    $map = [];
    foreach ($_SERVER as $name => $value) {
        if (string_starts_with((string)$name, 'HTTP_')) {
            $header = substr((string)$name, 5);
            $header = str_replace('_', ' ', $header);
            $header = ucwords(strtolower($header));
            $header = str_replace(' ', '-', $header);
            $map[$header] = $value;
        }
    }
    return $map;
}

function require_auth(): array
{
    $expectedToken = getenv('AGENT_NOTEBOOK_TOKEN') ?: '';
    if ($expectedToken === '') {
        fail('Server is missing AGENT_NOTEBOOK_TOKEN', 500);
    }

    $headers = get_headers_map();
    $authorization = get_header_value($headers, 'Authorization');
    $token = '';
    $agentName = trim((string)get_header_value($headers, 'X-Agent-Name'));

    if (preg_match('/^Bearer\\s+(.+)$/i', $authorization, $matches)) {
        $token = trim((string)$matches[1]);
    } elseif (isset($_GET['token'])) {
        $token = trim((string)$_GET['token']);
    } elseif (get_header_value($headers, 'X-Agent-Token')) {
        $token = trim((string)get_header_value($headers, 'X-Agent-Token'));
    }

    if ($token === '' || !hash_equals($expectedToken, $token)) {
        fail('Unauthorized', 401);
    }
    if ($agentName === '') {
        $agentName = 'agent-anonymous';
    }
    return ['agent' => $agentName];
}

function get_db(): PDO
{
    $basePath = __DIR__ . '/storage';
    if (!is_dir($basePath)) {
        if (!mkdir($basePath, 0775, true) && !is_dir($basePath)) {
            fail('Unable to create storage directory', 500);
        }
    }

    $dbFile = getenv('AGENT_NOTEBOOK_DB') ?: ($basePath . '/agent-notebook.sqlite');
    $drivers = class_exists('PDO') ? PDO::getAvailableDrivers() : [];
    if (!in_array('sqlite', $drivers, true)) {
        fail('SQLite PDO driver unavailable on this host. Install pdo_sqlite.', 500);
    }
    $pdo = new PDO('sqlite:' . $dbFile, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA foreign_keys = ON;');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS documents (' .
        'id INTEGER PRIMARY KEY AUTOINCREMENT,' .
        'path TEXT NOT NULL UNIQUE,' .
        'title TEXT NOT NULL,' .
        'content TEXT NOT NULL DEFAULT "",' .
        'agent_name TEXT NOT NULL,' .
        'created_at INTEGER NOT NULL,' .
        'updated_at INTEGER NOT NULL,' .
        'revision INTEGER NOT NULL DEFAULT 1' .
        ')'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS attachments (' .
        'id INTEGER PRIMARY KEY AUTOINCREMENT,' .
        'document_id INTEGER NOT NULL,' .
        'filename TEXT NOT NULL,' .
        'stored_name TEXT NOT NULL UNIQUE,' .
        'mime_type TEXT NOT NULL,' .
        'size_bytes INTEGER NOT NULL,' .
        'created_at INTEGER NOT NULL,' .
        'FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE' .
        ')'
    );

    $pdo->exec(
        "INSERT OR IGNORE INTO documents (path, title, content, agent_name, created_at, updated_at, revision) VALUES " .
        "('agents.md', 'agents.md', '## agents.md\n\nThis notebook is an agent-oriented collaboration surface.\n\n- Use markdown for all pages.\n- Keep page paths hierarchical, e.g. `team/ideas/current.md`.\n- Store sensitive credentials only in secure secret stores, never in content.\n', 'system', strftime('%s', 'now'), strftime('%s', 'now'), 1)"
    );

    return $pdo;
}

function parse_json_body(): array
{
    $raw = file_get_contents('php://input');
    if (!$raw) {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

function simple_markdown_to_html(string $markdown): string
{
    $html = htmlspecialchars($markdown, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $html = preg_replace('/^###\s*(.+)$/m', '<h3>$1</h3>', $html);
    $html = preg_replace('/^##\s*(.+)$/m', '<h2>$1</h2>', $html);
    $html = preg_replace('/^#\s*(.+)$/m', '<h1>$1</h1>', $html);
    $html = preg_replace('/```([\\s\\S]*?)```/', '<pre><code>$1</code></pre>', $html);
    $html = preg_replace('/\*\*(.+?)\*\*/s', '<strong>$1</strong>', $html);
    $html = preg_replace('/\*(.+?)\*/s', '<em>$1</em>', $html);
    $html = preg_replace('/`([^`]+)`/', '<code>$1</code>', $html);
    $html = preg_replace('/\\[(.*?)\\]\\((.*?)\\)/', '<a href="$2">$1</a>', $html);
    $lines = preg_split('/\\r?\\n/', $html);
    if (!is_array($lines)) {
        return '<p>' . nl2br((string)$html) . '</p>';
    }
    $inUl = false;
    $output = '';
    foreach ($lines as $line) {
        $trimmed = trim((string)$line);
        if ($trimmed === '') {
            if ($inUl) {
                $output .= "</ul>\n";
                $inUl = false;
            }
            continue;
        }
        if (string_starts_with($trimmed, '- ') || string_starts_with($trimmed, '* ')) {
            if (!$inUl) {
                $output .= "<ul>\n";
                $inUl = true;
            }
            $output .= '<li>' . substr($trimmed, 2) . "</li>\n";
            continue;
        }
        if ($inUl) {
            $output .= "</ul>\n";
            $inUl = false;
        }
        $output .= '<p>' . $line . "</p>\n";
    }
    if ($inUl) {
        $output .= "</ul>\n";
    }
    return $output;
}

function get_document(PDO $pdo, string $path): ?array
{
    $stmt = $pdo->prepare(
        'SELECT id, path, title, content, agent_name, created_at, updated_at, revision ' .
        'FROM documents WHERE path = :path'
    );
    $stmt->execute([':path' => $path]);
    $document = $stmt->fetch();
    if (!$document) {
        return null;
    }
    $stmt = $pdo->prepare(
        'SELECT id, filename, stored_name, mime_type, size_bytes ' .
        'FROM attachments WHERE document_id = :document_id ORDER BY id DESC'
    );
    $stmt->execute([':document_id' => (int)$document['id']]);
    $document['attachments'] = $stmt->fetchAll();
    return $document;
}

function save_document(PDO $pdo, string $path, string $title, string $content, string $agentName): array
{
    $now = time();
    $existing = get_document($pdo, $path);
    if ($existing) {
        $stmt = $pdo->prepare(
            'UPDATE documents SET title = :title, content = :content, agent_name = :agent_name, ' .
            'updated_at = :updated_at, revision = revision + 1 WHERE path = :path'
        );
        $stmt->execute([
            ':path' => $path,
            ':title' => $title,
            ':content' => $content,
            ':agent_name' => $agentName,
            ':updated_at' => $now,
        ]);
    } else {
        $stmt = $pdo->prepare(
            'INSERT INTO documents (path, title, content, agent_name, created_at, updated_at, revision) ' .
            'VALUES (:path, :title, :content, :agent_name, :created_at, :updated_at, 1)'
        );
        $stmt->execute([
            ':path' => $path,
            ':title' => $title,
            ':content' => $content,
            ':agent_name' => $agentName,
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);
    }
    return get_document($pdo, $path) ?: [];
}

function list_children(PDO $pdo, string $path = ''): array
{
    if ($path === '') {
        $stmt = $pdo->query(
            "SELECT path, title, updated_at FROM documents WHERE path NOT LIKE '%/%' ORDER BY path ASC"
        );
        return $stmt->fetchAll();
    }

    $prefix = rtrim($path, '/') . '/';
    $prefixLen = strlen($prefix);
    $stmt = $pdo->prepare(
        'SELECT path, title, updated_at FROM documents ' .
        'WHERE path LIKE :prefix AND path != :path AND substr(path, :prefix_len + 1) NOT LIKE "%/%" ' .
        'ORDER BY path ASC'
    );
    $stmt->execute([
        ':prefix' => $prefix . '%',
        ':path' => $path,
        ':prefix_len' => $prefixLen,
    ]);
    return $stmt->fetchAll();
}

function save_attachment(PDO $pdo, int $documentId, string $filename, string $storedName, string $mimeType, int $size): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO attachments (document_id, filename, stored_name, mime_type, size_bytes, created_at) ' .
        'VALUES (:document_id, :filename, :stored_name, :mime_type, :size_bytes, :created_at)'
    );
    $stmt->execute([
        ':document_id' => $documentId,
        ':filename' => $filename,
        ':stored_name' => $storedName,
        ':mime_type' => $mimeType,
        ':size_bytes' => $size,
        ':created_at' => time(),
    ]);
}

function get_storage_root(): string
{
    $path = __DIR__ . '/storage/attachments';
    if (!is_dir($path) && !mkdir($path, 0775, true) && !is_dir($path)) {
        fail('Unable to create attachment storage', 500);
    }
    return $path;
}

function handle_api(PDO $pdo, string $uri): void
{
    $method = strtoupper((string)$_SERVER['REQUEST_METHOD']);
    $uri = (string)$uri;
    $auth = require_auth();
    $agentName = $auth['agent'];

    if ($uri === '/api/page') {
        $pathRaw = isset($_GET['path']) ? trim((string)$_GET['path']) : '';
        try {
            $path = normalize_path($pathRaw);
        } catch (InvalidArgumentException $e) {
            fail($e->getMessage(), 400);
        }

        if ($method === 'GET') {
            if ($path === '') {
                fail('path is required', 400);
            }
            $document = get_document($pdo, $path);
            if (!$document) {
                fail('not found', 404);
            }

            $document['content_html'] = simple_markdown_to_html((string)$document['content']);
            $document['content_markdown'] = (string)$document['content'];
            $document['success'] = true;
            json_response($document, 200);
        }

        if ($method === 'POST' || $method === 'PUT') {
            $body = parse_json_body();
            $content = trim((string)($body['content'] ?? ''));
            $title = trim((string)($body['title'] ?? basename($path)));
            if ($path === '') {
                fail('path is required', 400);
            }
            $saved = save_document($pdo, $path, $title, $content, $agentName ?: trim((string)($body['agent'] ?? 'agent-anonymous')));
            $saved['content_html'] = simple_markdown_to_html((string)$saved['content']);
            $saved['content_markdown'] = (string)$saved['content'];
            $saved['success'] = true;
            json_response($saved, $method === 'POST' ? 201 : 200);
        }

        fail('method not allowed', 405);
    }

    if ($uri === '/api/children') {
        if ($method !== 'GET') {
            fail('method not allowed', 405);
        }
        $parent = '';
        if (isset($_GET['path'])) {
            try {
                $parent = normalize_path((string)$_GET['path']);
            } catch (InvalidArgumentException $e) {
                fail($e->getMessage(), 400);
            }
        }
        $children = list_children($pdo, $parent);
        json_response([
            'success' => true,
            'path' => $parent,
            'children' => $children,
        ]);
    }

    if ($uri === '/api/upload') {
        if ($method !== 'POST') {
            fail('method not allowed', 405);
        }
        if (!isset($_GET['path'])) {
            fail('path query parameter required', 400);
        }
        try {
            $path = normalize_path((string)$_GET['path']);
        } catch (InvalidArgumentException $e) {
            fail($e->getMessage(), 400);
        }

        if (!isset($_FILES['file'])) {
            fail('file is required', 400);
        }

        if (!isset($_FILES['file']['error']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
            fail('file upload failed', 400);
        }
        $tmp = (string)$_FILES['file']['tmp_name'];
        $sizeEnv = getenv('AGENT_NOTEBOOK_MAX_UPLOAD_BYTES');
        $sizeLimit = is_string($sizeEnv) && $sizeEnv !== '' ? (int)$sizeEnv : (8 * 1024 * 1024);
        if (!is_uploaded_file($tmp) || filesize($tmp) > $sizeLimit) {
            fail('file too large', 413);
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = (string)$finfo->file($tmp);
        $allowed = [
            'text/plain',
            'text/markdown',
            'text/x-markdown',
            'application/pdf',
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
        ];
        if (!in_array($mimeType, $allowed, true)) {
            fail('unsupported content type', 400);
        }

        $document = get_document($pdo, $path);
        if (!$document) {
            $document = save_document($pdo, $path, basename($path), '', $agentName);
            $document = get_document($pdo, $path);
        }
        if (!$document || !isset($document['id'])) {
            fail('failed to create document', 500);
        }

        $uploadPath = get_storage_root();
        $rawName = (string)($_FILES['file']['name'] ?? 'upload.bin');
        $safeName = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($rawName));
        $ext = pathinfo($safeName, PATHINFO_EXTENSION);
        $stored = bin2hex(random_bytes(16)) . '-' . time();
        if ($ext !== '') {
            $stored .= '.' . strtolower((string)$ext);
        }
        $dest = $uploadPath . '/' . $stored;
        if (!move_uploaded_file($tmp, $dest)) {
            fail('unable to move uploaded file', 500);
        }

        save_attachment($pdo, (int)$document['id'], $safeName, $stored, $mimeType, (int)$_FILES['file']['size']);

        json_response([
            'success' => true,
            'path' => $path,
            'attachment' => [
                'filename' => $safeName,
                'mime_type' => $mimeType,
                'size_bytes' => (int)$_FILES['file']['size'],
                'url' => '/api/attachment?id=' . (int)$pdo->lastInsertId(),
            ],
        ], 201);
    }

    if ($uri === '/api/attachment') {
        if ($method !== 'GET') {
            fail('method not allowed', 405);
        }
        $idRaw = $_GET['id'] ?? '';
        if ($idRaw === '' || !ctype_digit((string)$idRaw)) {
            fail('id is required', 400);
        }

        $stmt = $pdo->prepare(
            'SELECT a.filename, a.stored_name, a.mime_type, d.path AS document_path ' .
            'FROM attachments a ' .
            'JOIN documents d ON d.id = a.document_id ' .
            'WHERE a.id = :id'
        );
        $stmt->execute([':id' => (int)$idRaw]);
        $row = $stmt->fetch();
        if (!$row) {
            fail('not found', 404);
        }
        $filePath = get_storage_root() . '/' . $row['stored_name'];
        if (!is_file($filePath)) {
            fail('missing file', 404);
        }
        header('Content-Type: ' . $row['mime_type']);
        header('Content-Disposition: inline; filename="' . $row['filename'] . '"');
        readfile($filePath);
        exit;
    }

    if ($uri === '/api/agents.md') {
        if ($method !== 'GET') {
            fail('method not allowed', 405);
        }
        $document = get_document($pdo, 'agents.md');
        if (!$document) {
            fail('agents.md not found', 404);
        }
        $document['content_html'] = simple_markdown_to_html((string)$document['content']);
        $document['content_markdown'] = (string)$document['content'];
        $document['success'] = true;
        json_response($document);
    }

    fail('not found', 404);
}

function document_snippet(string $content, int $limit = 220): string
{
    $text = trim(strip_tags($content));
    $text = preg_replace('/\s+/', ' ', $text) ?: '';
    if ($text === '') {
        return '';
    }
    if (strlen($text) <= $limit) {
        return $text;
    }
    return substr($text, 0, max(0, $limit - 3)) . '...';
}

function recent_documents(PDO $pdo, int $limit = 12): array
{
    $limit = max(1, min(50, $limit));
    $stmt = $pdo->prepare(
        'SELECT path, title, content, updated_at FROM documents ORDER BY COALESCE(updated_at, id) DESC LIMIT :limit'
    );
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $documents = [];
    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $path = isset($row['path']) ? (string)$row['path'] : '';
        if ($path === '') {
            continue;
        }
        $title = isset($row['title']) ? (string)$row['title'] : '';
        if ($title === '') {
            $title = $path;
        }
        $content = isset($row['content']) ? (string)$row['content'] : '';

        $documents[] = [
            'path' => $path,
            'title' => $title,
            'snippet' => document_snippet($content, 220),
            'updated_at' => $row['updated_at'] ?? null,
        ];
    }

    return $documents;
}

function clean_doc_path_for_url(string $path): string
{
    $trimmed = trim($path);
    if ($trimmed === '') {
        return '';
    }
    $segments = preg_split('/\/+/', trim($trimmed, '/'));
    if ($segments === false || $segments === []) {
        return '';
    }
    $segments = array_values(array_filter($segments, 'strlen'));
    if (!$segments) {
        return '';
    }
    return implode('/', array_map('rawurlencode', $segments));
}

function is_image_mime(string $mimeType): bool
{
    $normalized = strtolower(trim($mimeType));
    return string_starts_with($normalized, 'image/');
}

function attachment_image_html(PDO $pdo, array $attachment): string
{
    if (!is_image_mime((string)($attachment['mime_type'] ?? ''))) {
        return '';
    }
    $storedName = trim((string)($attachment['stored_name'] ?? ''));
    if ($storedName === '') {
        return '';
    }
    $filePath = get_storage_root() . '/' . $storedName;
    if (!is_file($filePath)) {
        return '';
    }
    $mimeType = trim((string)($attachment['mime_type'] ?? 'image/png'));
    $data = file_get_contents($filePath);
    if ($data === false) {
        return '';
    }
    $encoded = base64_encode($data);
    $label = htmlspecialchars((string)($attachment['filename'] ?? $storedName), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<figure><img src="data:' . htmlspecialchars($mimeType, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . ';base64,' . $encoded . '" alt="' . $label . '" /><figcaption>' . $label . '</figcaption></figure>';
}

function render_document_view(PDO $pdo, string $path): string
{
    try {
        $normalized = normalize_path($path);
    } catch (InvalidArgumentException) {
        return '<section class="card selected-doc"><h3>Document</h3><p class="warn">Invalid document path.</p></section>';
    }

    if ($normalized === '') {
        return '<section class="card selected-doc"><h3>Document</h3><p class="small">Select a document from the left tree or latest list to preview it.</p></section>';
    }

    $document = get_document($pdo, $normalized);
    if (!$document) {
        return '<section class="card selected-doc"><h3>Document</h3><p class="warn">Document not found.</p></section>';
    }

    $title = htmlspecialchars((string)($document['title'] ?? $normalized), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $content = simple_markdown_to_html((string)($document['content'] ?? ''));
    $attachmentsHtml = '';
    $attachments = is_array($document['attachments'] ?? null) ? $document['attachments'] : [];
    if (!empty($attachments)) {
        $attachmentCards = '';
        foreach ($attachments as $attachment) {
            $attachmentCards .= attachment_image_html($pdo, (array)$attachment);
        }
        if (trim($attachmentCards) !== '') {
            $attachmentsHtml = '<div class="attachments"><h4>Attachments</h4>' . $attachmentCards . '</div>';
        }
    }

    $pathLabel = htmlspecialchars($normalized, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    return '<section class="card selected-doc"><h3>' . $title . '</h3><p class="small doc-path">' . $pathLabel . '</p><div class="doc-content">' . $content . '</div>' . $attachmentsHtml . '</section>';
}

function document_tree(PDO $pdo): array
{
    $stmt = $pdo->prepare('SELECT path, title, updated_at FROM documents ORDER BY path ASC');
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $tree = [];
    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $rawPath = trim((string)($row['path'] ?? ''));
        if ($rawPath === '') {
            continue;
        }
        $segments = preg_split('/\/+/', trim($rawPath, '/'));
        if ($segments === false) {
            continue;
        }
        $segments = array_values(array_filter($segments, 'strlen'));
        if (!$segments) {
            continue;
        }

        $node = &$tree;
        $segmentCount = count($segments);
        foreach ($segments as $index => $segment) {
            $safeSegment = $segment;
            if (!array_key_exists($safeSegment, $node)) {
                $node[$safeSegment] = [
                    'name' => $segment,
                    'children' => [],
                    'document' => null,
                ];
            }

            if ($index === $segmentCount - 1) {
                $node[$safeSegment]['document'] = [
                    'path' => $rawPath,
                    'title' => isset($row['title']) ? (string)$row['title'] : $rawPath,
                    'updated_at' => $row['updated_at'] ?? null,
                ];
                $node = &$node[$safeSegment]['children'];
            } else {
                $node = &$node[$safeSegment]['children'];
            }
        }
        unset($node);
    }

    return $tree;
}

function render_document_tree_html(array $tree): string
{
    if (empty($tree)) {
        return '<p class="small">No documents yet.</p>';
    }

    $renderNode = function (array $node) use (&$renderNode): string {
        ksort($node, SORT_STRING);
        $html = '<ul class="tree">';
        foreach ($node as $item) {
            $folderName = htmlspecialchars((string)($item['name'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $document = $item['document'] ?? null;
            $children = is_array($item['children'] ?? null) ? $item['children'] : [];

            $html .= '<li>';
            if (is_array($document)) {
                $path = (string)($document['path'] ?? '');
                $title = htmlspecialchars((string)($document['title'] ?? $path), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                $safePath = htmlspecialchars($path, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            $cleanPath = clean_doc_path_for_url($path);
            $docHref = $cleanPath === '' ? '/doc' : '/doc/' . $cleanPath;
            $html .= '<a href="' . $docHref . '" class="doc-link" data-doc-path="' . $safePath . '">' . $title . '</a>';
            } else {
                $html .= '<span class="folder">' . $folderName . '</span>';
            }

            if (!empty($children)) {
                $childContent = $renderNode($children);
                if ($childContent !== '<ul class="tree"></ul>') {
                    $html .= $childContent;
                }
            }
            $html .= '</li>';
        }
        $html .= '</ul>';

        return $html;
    };

    return $renderNode($tree);
}

function render_ui(PDO $pdo, string $selectedPath = ''): void
{
    $title = 'Agent Notebook';
    $recent = recent_documents($pdo, 12);
    $recent_json = json_encode($recent, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if ($recent_json === false) {
        $recent_json = '[]';
    }
    $tree_html = render_document_tree_html(document_tree($pdo));
    $querySelectedPath = isset($_GET['path']) ? trim((string)$_GET['path']) : '';
    $effectiveSelectedPath = $selectedPath !== '' ? $selectedPath : $querySelectedPath;
    $selectedDocument = render_document_view($pdo, $effectiveSelectedPath);
    echo <<<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>$title</title>
  <style>
    :root { color-scheme: dark; --bg:#090b11; --panel:#121826; --muted:#98a2b3; --text:#ecf0f6; --accent:#5dd6ff; --card:#1b2231; }
    html,body { margin:0; font-family: Inter, "Segoe UI", sans-serif; background: radial-gradient(circle at 25% 0%, #1a2236 0%, #090b11 52%, #090b11 100%); color: var(--text); min-height:100%; }
    .wrap{max-width:1100px;margin:0 auto;padding:20px}
    h1{margin:12px 0 2px}
    .hint{color:var(--muted); margin:0 0 18px}
    .layout{display:grid;grid-template-columns:360px 1fr;gap:16px}
    .card{background:var(--panel);border:1px solid #242f43;border-radius:16px;padding:14px}
    .small{color:#b4bfd3;font-size:12px}
    .tree-list{list-style:none;padding:0;margin:0}
    .tree-list ul{list-style:none;margin:6px 0 0;padding:0 0 0 16px}
    .tree-list li{margin:7px 0}
    .tree-list .folder{color:#9aa8be;font-weight:600;display:block}
    .tree-list .doc-link{color:var(--text);text-decoration:none}
    .tree-list .doc-link:hover{text-decoration:underline;color:var(--accent)}
    .doc-list{list-style:none;padding:0;margin:0}
    .doc-list li{margin-bottom:12px;padding:10px;border:1px solid #2c3a55;border-radius:10px;background:#101a2a}
    .doc-list a{display:block;color:var(--text);text-decoration:none;font-weight:600}
    .doc-list a:hover{text-decoration:underline;color:var(--accent)}
    .doc-snippet{margin:8px 0 0;color:#aeb8cc;font-size:13px;line-height:1.35}
    .workspace{margin-top:16px}
    .doc-content h1,.doc-content h2,.doc-content h3{margin-top:0}
    .doc-content pre{background:#060a14;padding:10px;border-radius:8px;overflow:auto}
    .doc-content code{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .doc-content img{max-width:100%;border-radius:8px;border:1px solid #28314a}
    .attachments{margin-top:16px}
    .attachments figure{margin:0 0 12px}
    .attachments img{display:block;max-width:100%;margin-bottom:8px}
    .attachments figcaption{font-size:12px;color:#9aa8be}
    .doc-path{word-break:break-all}
    pre{background:#060a14;padding:10px;border-radius:8px;overflow:auto}
    code{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .status{margin-top:10px;min-height:20px}
    .ok{color:#7ee787}
    .warn{color:#ffcc66}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Agent Notebook</h1>
    <p class="hint">A clean, read-only notebook for agents. Browse documents by hierarchy on the left and scan latest pages on the right.</p>
    <div class="status" id="status"></div>
    <div class="layout">
      <section class="card">
        <h3>Documents</h3>
        <div class="tree-list" style="margin-top:8px;">
          $tree_html
        </div>
      </section>
      <section class="card">
        <h3>Latest documents</h3>
        <ul id="recent-list" class="doc-list" style="margin-top:8px;"></ul>
        <p class="small" id="empty-state" style="display:none;color:#7f8aa0;margin-top:8px;">No uploads yet.</p>
      </section>
    </div>
    <section class="workspace">
      $selectedDocument
    </section>
  </div>
  <script>
    const statusEl = document.getElementById('status');
    const recentList = document.getElementById('recent-list');
    const emptyState = document.getElementById('empty-state');
    const recentPages = $recent_json;

    const setMessage = (msg, cls='warn') => {
      statusEl.textContent = msg;
      statusEl.className = 'status ' + cls;
    };

    const renderRecent = () => {
      recentList.innerHTML = '';
      if (!recentPages.length) {
        emptyState.style.display = 'block';
        return;
      }
      emptyState.style.display = 'none';
      recentPages.forEach((item) => {
        const li = document.createElement('li');
        const link = document.createElement('a');
        const snippet = document.createElement('p');
        const toDocUrl = (path) => '/doc/' + path.split('/').map(encodeURIComponent).join('/');
        link.href = toDocUrl(item.path);
        link.textContent = item.title || item.path;
        snippet.className = 'doc-snippet';
        snippet.textContent = item.snippet || '';
        li.appendChild(link);
        li.appendChild(snippet);
        recentList.appendChild(li);
      });
    };
    renderRecent();
    setMessage('Ready');
  </script>
</body>
</html>
HTML;
    exit;
}

load_environment_file(__DIR__ . '/.env');

$method = strtoupper((string)$_SERVER['REQUEST_METHOD']);
$uri = get_request_path();
$db = get_db();

if (strpos($uri, '/api/') === 0 || $uri === '/api' || $uri === '/api/agents.md') {
    if ($uri === '/api') {
        fail('api root', 404);
    }
    handle_api($db, $uri);
}

if ($uri === '/agents.md') {
    // Public render path that still uses token policy.
    require_auth();
    $doc = get_document($db, 'agents.md');
    if (!$doc) {
        fail('agents.md not found', 404);
    }
    header('Content-Type: text/markdown; charset=utf-8');
    echo (string)$doc['content'];
    exit;
}

if ($method === 'GET' && ($uri === '/' || $uri === '/doc' || string_starts_with($uri, '/doc/'))) {
    $selectedPath = '';
    if (string_starts_with($uri, '/doc/')) {
        $selectedPath = rawurldecode(substr($uri, 5));
    }
    render_ui($db, $selectedPath);
}

json_response(['success' => true, 'message' => 'Agent Notebook is running', 'routes' => ['/api/page', '/api/children', '/api/upload', '/api/attachment', '/api/agents.md']], 200);
?>
