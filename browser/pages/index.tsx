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

          await workerApi.generateProof(15);
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

          await workerApi.generateProofPreloadedVK(15);
        }}
      >
        Generate proof with VK
      </button>
    </main>
  );
}
