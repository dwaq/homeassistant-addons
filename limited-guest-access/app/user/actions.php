<?php
namespace TekniskSupport\LimitedGuestAccess\User;

class Actions {
    const     DATA_DIR           = '/data/links/';
    const     INJECT_DIR         = ['/data/', '/share/limited-guest-access/'];
    const     API_URL            = 'http://supervisor/core/api/';
    public    bool $passwordProtected = false;
    public    bool $authenticated     = false;
    public    bool $authFailed        = false;
    protected object $linkData;
    protected ?object $data;
    public    ?string $theme = null;

    public function __construct()
    {
        $this->boot();
    }

    protected function boot(): void
    {
        date_default_timezone_set($_SERVER["TZ"]);
        
        // MOVED: session_start() is removed from here. 
        // We will start it only after confirming we have a valid link.
        
        // Load and validate link data
        $this->loadLinkData();
        
        // Start session only if we have valid data (stops bots from filling disk with sessions)
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }

        // Handle authentication
        $this->handleAuthentication();
        
        // Handle actions if present
        $this->handleAction();
    }

    protected function loadLinkData(): void
    {
        $link = $this->getLink();
        
        if ($link === null) {
            $this->displayError("No link ID was provided. Please make sure you are accessing a valid link.");
        }

        $filePath = self::DATA_DIR . $link . '.json';
        
        if (!file_exists($filePath)) {
            $this->displayError("The requested link does not exist or is not authorized.");
        }
        
        $this->data = json_decode(file_get_contents($filePath));
        
        if (isset($this->data->linkData->theme)) {
            $this->theme = $this->data->linkData->theme;
        }
    }

    protected function displayError(string $message): void
    {
        http_response_code(401);
        echo "<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error</h1><p>{$message}</p></body></html>";
        exit;
    }

    protected function handleAuthentication(): void
    {
        if (isset($this->data->linkData->password) && !empty($this->data->linkData->password)) {
            $this->passwordProtected = true;
            $linkId = $this->getLink();
            $clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';

            // Initialize session arrays if needed
            if (!isset($_SESSION['authenticated_links'])) {
                $_SESSION['authenticated_links'] = [];
            }
            if (!isset($_SESSION['failed_attempts'])) {
                $_SESSION['failed_attempts'] = [];
            }

            // --- FIX START: Non-blocking Rate Limit ---
            $attemptKey = $linkId . '_' . $clientIp;
            
            // Check if user is currently blocked by time (Prevent sleep)
            if (isset($_SESSION['next_login_allowed'][$attemptKey]) && 
                time() < $_SESSION['next_login_allowed'][$attemptKey]) {
                $this->authFailed = true;
                return; // Exit immediately, do not verify password, do not sleep
            }
            // --- FIX END ---

            // Check for an existing session
            if (isset($_SESSION['authenticated_links'][$linkId])) {
                if (isset($_SESSION['authenticated_links'][$linkId]['login_time']) && (time() - $_SESSION['authenticated_links'][$linkId]['login_time'] < 3600)) {
                    $this->authenticated = true;
                } else {
                    unset($_SESSION['authenticated_links'][$linkId]);
                    $this->authFailed = true;
                }
            }

            // Handle a new login attempt
            if (isset($_POST['password'])) {
                $success = password_verify($_POST['password'], $this->data->linkData->password);

                // Log the attempt (Consider disabling this if I/O is too high during attacks)
                $this->logLoginAttempt($linkId, $clientIp, $success);

                if ($success) {
                    session_regenerate_id(true);
                    $_SESSION['authenticated_links'][$linkId] = ['login_time' => time()];
                    unset($_SESSION['failed_attempts'][$attemptKey]);
                    unset($_SESSION['next_login_allowed'][$attemptKey]); // Clear block
                    $this->authenticated = true;
                } else {
                    // Failed login - Calculate backoff
                    if (!isset($_SESSION['failed_attempts'][$attemptKey])) {
                        $_SESSION['failed_attempts'][$attemptKey] = 0;
                    }
                    $_SESSION['failed_attempts'][$attemptKey]++;

                    $failedCount = $_SESSION['failed_attempts'][$attemptKey];
                    $delay = pow(2, $failedCount);
                    $delay = min($delay, 60);

                    // --- FIX START: Set future timestamp instead of sleeping ---
                    if (!isset($_SESSION['next_login_allowed'])) {
                        $_SESSION['next_login_allowed'] = [];
                    }
                    $_SESSION['next_login_allowed'][$attemptKey] = time() + $delay;
                    // sleep($delay); // REMOVED: This was causing the crashes
                    // --- FIX END ---

                    $this->authFailed = true;
                }
            }
        }
    }

    protected function handleAction(): void
    {
        if (isset($_GET['action'])) {
            // Security check: Ensure user is authenticated before performing any action
            if ($this->passwordProtected && !$this->authenticated) {
                $this->displayError("You are not authorized to perform this action. Please log in.");
            }

            $availableActions = $this->getFilteredActions();
            $actionData = $availableActions->{$this->getAction()} ?? null;
            
            if (!$actionData) {
                throw new \Exception('Unknown action');
            }

            $this
                ->performAction($actionData)
                ->addLog($this->getAction())
                ->invalidateAction($actionData, $this->getAction())
                ->redirect('?performedAction=' . urlencode($actionData->friendly_name));
        }
    }

    public function getAllActions(): object
    {

        return $this->data;
    }

    public function getFilteredActions(): object
    {
        $filteredActions = (object)[];
        $allActions = clone $this->getAllActions(); // Use a clone to prevent modification of the original object
        if (isset($allActions->linkData)) {
            $this->linkData = $allActions->linkData;
            unset($allActions->linkData);
        }
        foreach ($allActions as $id => $action) {
            if ($this->validateTime($action)) {
                $filteredActions->{$id} = $action;
            }
        }

        return $filteredActions;
    }

    protected function validateTime(object $actionData): bool
    {
        $now        = time();
        $validFrom  = strtotime($actionData->valid_from);
        $expiryTime = strtotime($actionData->expiry_time);


        if ($expiryTime && $expiryTime <= $now) {
            return false;
        }

        if ($validFrom && $validFrom >= $now) {
            return false;
        }

        return true;
    }

    protected function addLog(string $actionId): self
    {
        $time = new \DateTime();
        $actions = $this->getAllActions();
        if (!isset($actions->$actionId->last_used)) {
            $actions->$actionId->last_used = [];
        }
        $actions->$actionId->last_used[] = $time->format('U');
        file_put_contents(self::DATA_DIR . $this->getLink() . '.json', json_encode($actions));

        return $this;
    }

    protected function invalidateAction(object $actionData, string $actionId): self
    {
        if ($actionData->one_time_use) {
            $actions = (array)$this->getAllActions();
            unset($actions[$actionId]);
            file_put_contents(self::DATA_DIR . $this->getLink() . '.json', json_encode($actions));
        }

        return $this;
    }

    protected function performAction(object $actionData): self
    {
        $data = (object) array_filter((array) $actionData->service_call_data) ?? [];
        $data = json_encode($data);
        $serviceCall = explode('.', $actionData->service_call);

        $ch = curl_init(self::API_URL . 'services/' . $serviceCall[0] . '/' . $serviceCall[1]);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer {$_SERVER['SUPERVISOR_TOKEN']}",
            'Content-Type: application/json',
            'Content-Length: ' . mb_strlen($data)
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);

        return $this;
    }

    protected function getLink(): ?string
    {
        $link = filter_input(INPUT_GET, 'link', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if ($link === null) {
            $link = filter_input(INPUT_POST, 'link', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        }
        
        if ($link && ctype_xdigit($link)) {
            return $link;
        } elseif ($link && preg_match('/^([a-zA-Z0-9_-]+)$/', $link)) {
            return $link;
        } else {
            return null; // Return null instead of throwing an exception
        }
    }

    protected function getAction(): string
    {
        $action = filter_input(INPUT_GET, 'action', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if ($action) {
            return $action;
        } else {
            throw new \Exception('No action given!');
        }
    }

    protected function redirect(string $path): self
    {
        header("Location: ". $path);

        return $this;
    }

    protected function logLoginAttempt(string $linkId, string $ipAddress, bool $success): void
    {
        $logFile = '/data/login_attempts.json';
        $attempts = [];

        if (file_exists($logFile)) {
            $attempts = json_decode(file_get_contents($logFile), true) ?? [];
        }

        $attempts[] = [
            'timestamp' => time(),
            'link_id' => $linkId,
            'ip_address' => $ipAddress,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'success' => $success
        ];

        // Keep only the last 1000 attempts to prevent the file from growing too large
        if (count($attempts) > 1000) {
            $attempts = array_slice($attempts, -1000);
        }

        file_put_contents($logFile, json_encode($attempts, JSON_PRETTY_PRINT));
    }

    public function getState(string $entityId): bool|string
    {
        $ch = curl_init(self::API_URL . 'states/'. $entityId);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "Authorization: Bearer {$_SERVER['SUPERVISOR_TOKEN']}"
        ]);

        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }

    public function injectHeader(): ?string
    {
        $headerFile = '/data/header.htm';
        if (file_exists($headerFile)) {
            return file_get_contents($headerFile);
        }
        $headerFile = '/share/limited-guest-access/header.htm';
        if (file_exists($headerFile)) {
            return file_get_contents($headerFile);
        }
        return null;
    }

    public function injectFooter(): ?string
    {
        $footerFile = '/data/footer.htm';
        if (file_exists($footerFile)) {
            return file_get_contents($footerFile);
        }
        $footerFile = '/share/limited-guest-access/footer.htm';
        if (file_exists($footerFile)) {
            return file_get_contents($footerFile);
        }
        return null;
    }

    public function getCustomCss(): ?string
    {
        // Try to load custom CSS from /data/style.css first (UI-managed)
        $cssFile = '/data/style.css';
        if (file_exists($cssFile)) {
            return file_get_contents($cssFile);
        }
        
        // If not found in /data/, try to load from /share/limited-guest-access/style.css (legacy file-based)
        $legacyCssFile = '/share/limited-guest-access/style.css';
        if (file_exists($legacyCssFile)) {
            return file_get_contents($legacyCssFile);
        }
        
        return null;
    }

    public function getCustomJs(): ?string
    {
        $jsFile = '/data/script.js';
        if (file_exists($jsFile)) {
            return file_get_contents($jsFile);
        }

        $legacyJsFile = '/share/limited-guest-access/script.js';
        if (file_exists($legacyJsFile)) {
            return file_get_contents($legacyJsFile);
        }
        return null;
    }
}
