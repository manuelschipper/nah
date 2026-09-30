#!/usr/bin/env tsx
import { spawnSync } from "node:child_process";

spawnSync("python3", ["helper.py", "--tenant", "acme"]);
