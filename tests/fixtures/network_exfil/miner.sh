#!/bin/sh
# Synthetic fixture: cryptominer launch (MITRE T1496).
./xmrig -o stratum+tcp://pool.example.invalid:3333 -u wallet --donate-level 1
