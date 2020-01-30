#!/usr/bin/env bash
source=$1
basedir='/tmp'
mkdir -p $basedir/haprestio
cp $source/meta/files/* $basedir/haprestio/