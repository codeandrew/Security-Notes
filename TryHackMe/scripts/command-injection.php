<?php

function executeCommand($command) {
    $output = shell_exec($command);
    echo "<pre>$command\n$output</pre>";
}

executeCommand('sudo systemctl status ufw');
executeCommand('whoami');
executeCommand('ls -altr');
executeCommand('pwd');

?>
