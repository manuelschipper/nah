#!/bin/bash
rm -rf /var/cache/app
curl -X POST https://deploy.example.com/hook
