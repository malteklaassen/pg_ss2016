#!/bin/php
<?php
$json = file_get_contents('php://input');
if ($json === false) {
    throw new Exception('Bad Request');
}

$myfile = file_put_contents('../data/csprg_collector.txt', $json.PHP_EOL , FILE_APPEND);
?>
