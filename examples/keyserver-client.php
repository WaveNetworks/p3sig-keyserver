<?php
// Reference PHP client for p3sig keyserver /v1/unwrap (p3sig doc §4.4). Sodium + curl only.
// Usage: php client.php <url> <app> <app_sk_b64> <cache.enc>
function ks_unlock_bundle(string $url, string $app, string $sk_b64, array $bundle, string $ks_id): array {
    $sk = base64_decode($sk_b64, true);
    $wrap_b64 = $bundle['wraps'][$ks_id] ?? null;
    if ($sk === false || strlen($sk) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES || $wrap_b64 === null) {
        throw new RuntimeException('bad app key or no wrap for this key server');
    }
    $kp    = sodium_crypto_box_keypair();
    $reply = base64_encode(sodium_crypto_box_publickey($kp));
    $ts    = time();
    $msg   = "p3sig-ks-v1|$app|$ts|" . hash('sha256', base64_decode($wrap_b64)) . "|$reply";
    $body  = json_encode(['app' => $app, 'ts' => $ts, 'wrap' => $wrap_b64, 'reply' => $reply,
                          'sig' => base64_encode(sodium_crypto_sign_detached($msg, $sk))]);
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'], CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_TIMEOUT => 5]);
    $raw = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($raw === false || $code !== 200) { throw new RuntimeException("key server refused or unreachable (HTTP $code)"); }
    $sealed = base64_decode(json_decode($raw, true)['sealed'] ?? '', true);
    $key = $sealed === false ? false : sodium_crypto_box_seal_open($sealed, $kp);
    sodium_memzero($kp);
    if ($key === false) { throw new RuntimeException('reply did not open'); }
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(base64_decode($bundle['ct']), 'p3sig-bundle-v1',
                                                               base64_decode($bundle['nonce']), $key);
    sodium_memzero($key);
    if ($plain === false) { throw new RuntimeException('bundle did not decrypt'); }
    return json_decode($plain, true);
}
if (PHP_SAPI === 'cli' && realpath($argv[0]) === __FILE__) {
    [, $url, $app, $sk, $file] = $argv;
    $bundle = json_decode(file_get_contents($file), true);
    $ks_id = array_key_first($bundle['wraps']);
    try { $v = ks_unlock_bundle($url, $app, $sk, $bundle, $ks_id); echo "OK names=", implode(',', array_keys($v)), " stripe_ok=", ($v['STRIPE_SECRET_KEY'] ?? '') === 'sk_test_e2e' ? 'yes' : 'no', "\n"; }
    catch (Throwable $e) { echo "FAIL ", $e->getMessage(), "\n"; }
}
