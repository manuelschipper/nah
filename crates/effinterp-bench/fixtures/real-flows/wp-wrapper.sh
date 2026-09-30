#!/bin/sh

WP_CLI_PHP=php
export WP_CLI_PHP
exec "$WP_CLI_PHP" wp-cli.php "$@"
