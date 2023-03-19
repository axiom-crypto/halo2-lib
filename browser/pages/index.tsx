import { wrap } from "comlink";

export default function Home() {
  return (
    <div>
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

          await workerApi.generateProof();
        }}
      >
        Generate proof
      </button>
    </div>
  );
}
