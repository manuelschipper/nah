#!/bin/sh
psql -h db -d app -c 'UPDATE audit.events SET seen=true'
