<?php
// ws-server.php
// Simple WebSocket signaling server in plain PHP (CLI). NOT production hardened.
// Run: php ws-server.php

set_time_limit(0);
ob_implicit_flush();

$address = '0.0.0.0';
$port = 8080;

$master = stream_socket_server("tcp://$address:$port", $errno, $errstr);
if (!$master) {
    echo "Failed to create socket: $errstr ($errno)\n";
    exit(1);
}
stream_set_blocking($master, false);
echo "WebSocket server listening on ws://$address:$port\n";

// Keep clients and room map
$clients = []; // fd => ['socket'=>..., 'handshake'=>bool, 'id'=>string, 'room'=>string]
$rooms = [];   // room => array of client ids

function generateId() {
    return bin2hex(random_bytes(8));
}

function performHandshake($client, $headers) {
    if (!preg_match("/Sec-WebSocket-Key: (.*)\r\n/", $headers, $matches)) return false;
    $key = trim($matches[1]);
    $accept = base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
    $upgrade = "HTTP/1.1 101 Switching Protocols\r\n" .
               "Upgrade: websocket\r\n" .
               "Connection: Upgrade\r\n" .
               "Sec-WebSocket-Accept: $accept\r\n\r\n";
    fwrite($client, $upgrade);
    return true;
}

function wsEncode($payload) {
    $len = strlen($payload);
    if ($len <= 125) $header = pack('CC', 0x81, $len);
    elseif ($len <= 65535) $header = pack('CCn', 0x81, 126, $len);
    else $header = pack('CCNN', 0x81, 127, $len); // not strictly correct for >32bit
    return $header . $payload;
}

function wsDecode($data) {
    $bytes = ord($data[1]) & 127;
    $offset = 2;
    if ($bytes === 126) {
        $mask = substr($data, 4, 4);
        $payload = substr($data, 8);
    } elseif ($bytes === 127) {
        $mask = substr($data, 10, 4);
        $payload = substr($data, 14);
    } else {
        $mask = substr($data, 2, 4);
        $payload = substr($data, 6);
    }
    $out = '';
    for ($i = 0, $len = strlen($payload); $i < $len; $i++) {
        $out .= $payload[$i] ^ $mask[$i % 4];
    }
    return $out;
}

while (true) {
    $read = $clients_sockets = [];
    $read[] = $master;
    foreach ($clients as $k => $v) {
        $read[] = $v['socket'];
    }

    $w = $e = null;
    if (stream_select($read, $w, $e, null) > 0) {
        foreach ($read as $sock) {
            if ($sock === $master) {
                $newsock = @stream_socket_accept($master, 0);
                if ($newsock) {
                    stream_set_blocking($newsock, false);
                    $id = generateId();
                    $clients[$id] = ['socket' => $newsock, 'handshake' => false, 'id' => $id, 'room' => null];
                    echo "Client $id connected\n";
                }
            } else {
                $data = @fread($sock, 2048);
                if ($data === '' || $data === false) {
                    // closed connection
                    $closedId = null;
                    foreach ($clients as $cid => $meta) if ($meta['socket'] === $sock) $closedId = $cid;
                    if ($closedId) {
                        echo "Client $closedId disconnected\n";
                        // remove from room
                        $room = $clients[$closedId]['room'];
                        if ($room && isset($rooms[$room])) {
                            $rooms[$room] = array_filter($rooms[$room], function($v) use ($closedId){return $v !== $closedId;});
                            // notify remaining in room
                            foreach ($rooms[$room] as $peerId) {
                                $msg = json_encode(['type'=>'peer-left','id'=>$closedId]);
                                fwrite($clients[$peerId]['socket'], wsEncode($msg));
                            }
                        }
                        fclose($clients[$closedId]['socket']);
                        unset($clients[$closedId]);
                    }
                } else {
                    // find which client
                    $clientId = null;
                    foreach ($clients as $cid => $meta) if ($meta['socket'] === $sock) $clientId = $cid;
                    if ($clientId === null) continue;

                    if (!$clients[$clientId]['handshake']) {
                        // first message is HTTP headers for handshake
                        if (performHandshake($sock, $data)) {
                            $clients[$clientId]['handshake'] = true;
                            // send ack with assigned id
                            $payload = json_encode(['type'=>'welcome','id'=>$clientId]);
                            fwrite($sock, wsEncode($payload));
                        } else {
                            fclose($sock);
                            unset($clients[$clientId]);
                        }
                    } else {
                        $msg = wsDecode($data);
                        $obj = json_decode($msg, true);
                        if (!$obj) continue;

                        // handle message types: create/join/offer/answer/ice/chat
                        $type = $obj['type'] ?? '';
                        if ($type === 'create' || $type === 'join') {
                            $room = $obj['room'];
                            $clients[$clientId]['room'] = $room;
                            if (!isset($rooms[$room])) $rooms[$room] = [];
                            // send participants list to joining client
                            $existing = $rooms[$room];
                            $rooms[$room][] = $clientId;
                            // notify joiner of its id and existing peers
                            $payload = json_encode(['type'=>'room-joined','peers'=>$existing,'id'=>$clientId]);
                            fwrite($sock, wsEncode($payload));
                            // notify existing peers about new peer
                            foreach ($existing as $peerId) {
                                $notify = json_encode(['type'=>'peer-joined','id'=>$clientId]);
                                fwrite($clients[$peerId]['socket'], wsEncode($notify));
                            }
                            echo "Client $clientId joined room $room\n";
                        } elseif (in_array($type, ['offer','answer','ice','chat'])) {
                            // relay to target
                            $target = $obj['target'] ?? null;
                            if ($target && isset($clients[$target])) {
                                // attach sender id
                                $obj['from'] = $clientId;
                                fwrite($clients[$target]['socket'], wsEncode(json_encode($obj)));
                            }
                        } elseif ($type === 'list-rooms') {
                            $list = array_keys($rooms);
                            fwrite($sock, wsEncode(json_encode(['type'=>'room-list','rooms'=>$list])));
                        }
                    }
                }
            }
        }
    }
}
