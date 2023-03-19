#!/bin/bash

for i in {11..19}; do
  cat "./src/secp256k1/configs/$i.config"
  echo ""
  cat "./src/secp256k1/configs/$i.config" > "./src/secp256k1/params.rs"
  wasm-pack build --target web --out-dir "../browser/lib/halo2Prover/wasm$i"
done

