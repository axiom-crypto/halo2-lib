import { expose } from "comlink";

const fetch_kzg_params = async (k: any) => {
  const response = await fetch(`/params_${k}.bin`, {
    method: "GET",
    mode: "cors",
    headers: {
      "Content-Type": "application/octet-stream", // set content type to binary
    },
  });
  const bytes = await response.arrayBuffer();

  const params = new Uint8Array(bytes);
  return params;
};

export const generateProof = async () => {
  console.log("Scalar mult proof");
  const params = await fetch_kzg_params(16);
  console.log("params", params);

  const {
    default: init,
    initThreadPool,
    prove,
    init_panic_hook,
  } = await import("./wasm/halo2_ecc.js");

  console.log("number of threads", navigator.hardwareConcurrency);

  await init();
  await init_panic_hook();
  await initThreadPool(navigator.hardwareConcurrency);
  console.time("Full proving time");
  const proof = await prove(params);
  console.timeEnd("Full proving time");
  console.log("proof", proof);
};

const exports = {
  generateProof,
};
export type Halo2Prover = typeof exports;

expose(exports);
