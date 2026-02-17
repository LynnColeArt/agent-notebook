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

function render_ui(string $token): void
{
    $token = htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $title = 'Agent Notebook';
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
    .toolbar{display:grid;grid-template-columns:1fr 2fr 1fr 1fr;gap:8px;margin-bottom:12px}
    .toolbar input,.toolbar button{padding:10px;border-radius:10px;border:1px solid #2a3449;background:#0f1624;color:var(--text)}
    .toolbar button{background:#1d2b44; cursor:pointer}
    .main{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .card{background:var(--panel);border:1px solid #242f43;border-radius:16px;padding:14px}
    textarea{width:100%;min-height:430px;background:#0f1624;color:var(--text);border:1px solid #29354b;border-radius:10px;padding:12px;font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .small{display:flex;justify-content:space-between;align-items:center;color:#b4bfd3;font-size:12px}
    .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace}
    .preview{background:var(--panel);padding:12px;border:1px solid #27334a;border-radius:10px;min-height:430px;white-space:pre-wrap;line-height:1.45}
    .preview h1,.preview h2,.preview h3{margin-top:0}
    .meta{display:flex;gap:10px;flex-wrap:wrap}
    .meta span{display:inline-block;border:1px solid #31405e;padding:5px 10px;border-radius:999px}
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
    <p class="hint">A minimal markdown notebook for agents. Token-protected API, hierarchical pages, attachments, and markdown rendering.</p>
    <div class="toolbar">
      <input id="token" type="password" placeholder="AGENT NOTEBOOK TOKEN" value="$token" />
      <input id="path" placeholder="Path (example: projects/agent-001/plan.md)" />
      <input id="title" placeholder="Title" />
      <input id="agent" placeholder="Agent name" />
    </div>
    <div class="toolbar">
      <button id="load">Load</button>
      <button id="save">Save</button>
      <button id="renderBtn">Render Preview</button>
      <button id="childrenBtn">List Children</button>
    </div>
    <div class="status" id="status"></div>
    <div class="main">
      <section class="card">
        <h3>Markdown Content</h3>
        <textarea id="content" placeholder="Write markdown here..."></textarea>
        <div style="margin-top:10px">
          <div class="small">Upload attachment (text/image)</div>
          <input id="file" type="file" accept=".txt,.md,.csv,.jpg,.jpeg,.png,.gif,.webp,.pdf" />
          <button id="upload">Upload File</button>
          <div id="attachmentStatus" class="status"></div>
        </div>
      </section>
      <section class="card">
        <h3>Rendered Preview</h3>
          <div id="preview" class="preview"></div>
          <div class="small" style="margin-top:12px">Current metadata</div>
          <div id="meta" class="meta"></div>
          <div id="attachmentList" class="small" style="margin-top:12px;"></div>
          <div class="small" style="margin-top:12px">Children</div>
          <ul id="children"></ul>
      </section>
    </div>
  </div>
  <script>
    const statusEl = document.getElementById('status');
    const attachmentStatus = document.getElementById('attachmentStatus');
    const getAuthHeaders = () => ({
      'Authorization': 'Bearer ' + (document.getElementById('token').value || '').trim()
    });

    const setMessage = (msg, cls='warn') => {
      statusEl.textContent = msg;
      statusEl.className = 'status ' + cls;
    };

    const renderMeta = (doc) => {
      const meta = document.getElementById('meta');
      if (!doc) {
        meta.innerHTML = '';
        return;
      }
      meta.innerHTML = [
        `<span>revision \${doc.revision || 1}</span>`,
        `<span>agent \${doc.agent_name || ''}</span>`,
        `<span>updated \${doc.updated_at || ''}</span>`,
        `<span>attachments \${((doc.attachments || []).length)}</span>`
      ].join('');

      const attachmentList = document.getElementById('attachmentList');
      if ((doc.attachments || []).length) {
        const lines = (doc.attachments || []).map(a => `<a href="/api/attachment?id=\${a.id}" target="_blank">\${a.filename}</a> (\${a.size_bytes} bytes)`).join(' · ');
        attachmentList.innerHTML = `Attachments: \${lines}`;
      } else {
        attachmentList.textContent = '';
      }
    };

    const loadPage = async () => {
      const path = document.getElementById('path').value.trim();
      if (!path) {
        setMessage('Path is required');
        return;
      }
      setMessage('Loading...');
      const resp = await fetch('/api/page?path=' + encodeURIComponent(path), {
        headers: getAuthHeaders()
      });
      const body = await resp.json();
      if (!resp.ok) {
        setMessage(body.error || 'Load failed');
        return;
      }
      document.getElementById('title').value = body.title || '';
      document.getElementById('content').value = body.content_markdown || '';
      document.getElementById('agent').value = body.agent_name || '';
      document.getElementById('preview').innerHTML = body.content_html || '';
      renderMeta(body);
      setMessage('Loaded', 'ok');
    };

    const savePage = async () => {
      const path = document.getElementById('path').value.trim();
      if (!path) {
        setMessage('Path is required');
        return;
      }
      const payload = {
        title: document.getElementById('title').value.trim(),
        content: document.getElementById('content').value,
        agent: document.getElementById('agent').value.trim() || 'agent-anonymous'
      };
      const resp = await fetch('/api/page?path=' + encodeURIComponent(path), {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
      const body = await resp.json();
      if (!resp.ok) {
        setMessage(body.error || 'Save failed');
        return;
      }
      document.getElementById('preview').innerHTML = body.content_html || '';
      renderMeta(body);
      setMessage('Saved', 'ok');
    };

    const renderNow = async () => {
      const path = document.getElementById('path').value.trim();
      if (!path) {
        setMessage('Path is required');
        return;
      }
      const resp = await fetch('/api/page?path=' + encodeURIComponent(path) + '&format=html', {
        headers: getAuthHeaders()
      });
      const body = await resp.json();
      if (!resp.ok) {
        setMessage(body.error || 'Render failed');
        return;
      }
      document.getElementById('preview').innerHTML = body.content_html || '';
      setMessage('Rendered', 'ok');
    };

    const loadChildren = async () => {
      const path = document.getElementById('path').value.trim();
      const endpoint = '/api/children' + (path ? '?path=' + encodeURIComponent(path) : '');
      const resp = await fetch(endpoint, { headers: getAuthHeaders() });
      const body = await resp.json();
      if (!resp.ok) {
        setMessage(body.error || 'Children failed');
        return;
      }
      const list = document.getElementById('children');
      list.innerHTML = '';
      (body.children || []).forEach(item => {
        const li = document.createElement('li');
        const btn = document.createElement('button');
        btn.textContent = item.path;
        btn.onclick = () => {
          document.getElementById('path').value = item.path;
          loadPage();
        };
        li.appendChild(btn);
        list.appendChild(li);
      });
      setMessage('Children loaded', 'ok');
    };

    const uploadFile = async () => {
      const path = document.getElementById('path').value.trim();
      const fileEl = document.getElementById('file');
      if (!path) {
        attachmentStatus.textContent = 'Path required for upload';
        return;
      }
      if (!fileEl.files || !fileEl.files.length) {
        attachmentStatus.textContent = 'Select file first';
        return;
      }
      const form = new FormData();
      form.append('file', fileEl.files[0]);
      const resp = await fetch('/api/upload?path=' + encodeURIComponent(path), {
        method: 'POST',
        headers: getAuthHeaders(),
        body: form
      });
      const body = await resp.json();
      attachmentStatus.textContent = resp.ok ? ('Uploaded: ' + (body.attachment ? body.attachment.filename : 'ok')) : (body.error || 'Upload failed');
      if (resp.ok) {
        await loadPage();
      }
    };

    document.getElementById('load').onclick = loadPage;
    document.getElementById('save').onclick = savePage;
    document.getElementById('renderBtn').onclick = renderNow;
    document.getElementById('childrenBtn').onclick = loadChildren;
    document.getElementById('upload').onclick = uploadFile;
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

if ($method === 'GET' && $uri === '/') {
    $token = getenv('AGENT_NOTEBOOK_TOKEN') ?: '';
    render_ui((string)$token);
}

json_response(['success' => true, 'message' => 'Agent Notebook is running', 'routes' => ['/api/page', '/api/children', '/api/upload', '/api/attachment', '/api/agents.md']], 200);
?>
