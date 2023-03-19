#!/bin/bash

for i in {11..19}; do
  cat "./src/secp256k1/configs/$i.config"
  cat "./src/secp256k1/configs/$i.config" > "./src/secp256k1/configs/ecdsa_circuit.tmp.config"
  wasm-pack build --target web --out-dir "../browser/lib/halo2Prover/wasm$i"
done
rm ./src/secp256k1/configs/ecdsa_circuit.tmp.config

