#!/bin/sh
# SYNTHETIC fixture — GTFOBins living-off-the-land binary abuse (tar shell breakout).
# Payload shape sourced from GTFOBins (https://gtfobins.github.io/, tar/shell).
# Used to prove the lolbin_unix pack detects LOLBin abuse. NOT live malware.
tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
