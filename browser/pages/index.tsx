import { wrap } from "comlink";

export default function Home() {
  return (
    <main>
      <button
        onClick={async () => {
          const worker = new Worker(
            new URL("../lib/halo2Prover/halo2Prover", import.meta.url),
            {
              name: "halo-worker",
              type: "module",
            }
          );

          const workerApi =
            wrap<import("../lib/halo2Prover/halo2Prover").Halo2Prover>(worker);

          for (let k = 11; k <= 19; k++) {
            await workerApi.generateProof(k);
          }
        }}
      >
        Generate proof
      </button>
      <br />
      <br />
      <button
        onClick={async () => {
          const worker = new Worker(
            new URL("../lib/halo2Prover/halo2Prover", import.meta.url),
            {
              name: "halo-worker",
              type: "module",
            }
          );

          const workerApi =
            wrap<import("../lib/halo2Prover/halo2Prover").Halo2Prover>(worker);

          for (let k = 11; k <= 19; k++) {
            await workerApi.generateProofPreloadedVK(k);
          }
        }}
      >
        Generate proof with VK
      </button>
    </main>
  );
}
