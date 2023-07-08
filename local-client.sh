#!/bin/sh

cargo build && sudo ./target/debug/nikau client 127.0.0.1
