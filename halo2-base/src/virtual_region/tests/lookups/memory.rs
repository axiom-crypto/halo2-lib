use crate::halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{keygen_pk, keygen_vk, Advice, Circuit, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use test_log::test;

use crate::{
    gates::{
        flex_gate::{threads::SinglePhaseCoreManager, FlexGateConfig, FlexGateConfigParams},
        GateChip, GateInstructions,
    },
    utils::{
        fs::gen_srs,
        halo2::raw_assign_advice,
        testing::{check_proof, gen_proof},
        ScalarField,
    },
    virtual_region::{lookups::LookupAnyManager, manager::VirtualRegionManager},
};

#[derive(Clone, Debug)]
struct RAMConfig<F: ScalarField> {
    cpu: FlexGateConfig<F>,
    copy: Vec<[Column<Advice>; 2]>,
    // dynamic lookup table
    memory: [Column<Advice>; 2],
}

#[derive(Clone, Default)]
struct RAMConfigParams {
    cpu: FlexGateConfigParams,
    copy_columns: usize,
}

struct RAMCircuit<F: ScalarField, const CYCLES: usize> {
    // private memory input
    memory: Vec<F>,
    // memory accesses
    ptrs: [usize; CYCLES],

    cpu: SinglePhaseCoreManager<F>,
    ram: LookupAnyManager<F, 2>,

    params: RAMConfigParams,
}

impl<F: ScalarField, const CYCLES: usize> RAMCircuit<F, CYCLES> {
    fn new(
        memory: Vec<F>,
        ptrs: [usize; CYCLES],
        params: RAMConfigParams,
        witness_gen_only: bool,
    ) -> Self {
        let cpu = SinglePhaseCoreManager::new(witness_gen_only, Default::default());
        let ram = LookupAnyManager::new(witness_gen_only, cpu.copy_manager.clone());
        Self { memory, ptrs, cpu, ram, params }
    }

    fn compute(&mut self) {
        let gate = GateChip::default();
        let ctx = self.cpu.main();
        let mut sum = ctx.load_constant(F::ZERO);
        for &ptr in &self.ptrs {
            let value = self.memory[ptr];
            let ptr = ctx.load_witness(F::from(ptr as u64 + 1));
            let value = ctx.load_witness(value);
            self.ram.add_lookup((ctx.type_id(), ctx.id()), [ptr, value]);
            sum = gate.add(ctx, sum, value);
        }
    }
}

impl<F: ScalarField, const CYCLES: usize> Circuit<F> for RAMCircuit<F, CYCLES> {
    type Config = RAMConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = RAMConfigParams;

    fn params(&self) -> Self::Params {
        self.params.clone()
    }

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        let k = params.cpu.k;
        let mut cpu = FlexGateConfig::configure(meta, params.cpu);
        let copy: Vec<_> = (0..params.copy_columns)
            .map(|_| {
                [(); 2].map(|_| {
                    let advice = meta.advice_column();
                    meta.enable_equality(advice);
                    advice
                })
            })
            .collect();
        let mem = [meta.advice_column(), meta.advice_column()];

        for copy in &copy {
            meta.lookup_any("dynamic memory lookup table", |meta| {
                let mem = mem.map(|c| meta.query_advice(c, Rotation::cur()));
                let copy = copy.map(|c| meta.query_advice(c, Rotation::cur()));
                vec![(copy[0].clone(), mem[0].clone()), (copy[1].clone(), mem[1].clone())]
            });
        }
        log::info!("Poisoned rows: {}", meta.minimum_rows());
        cpu.max_rows = (1 << k) - meta.minimum_rows();

        RAMConfig { cpu, copy, memory: mem }
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "RAM Circuit",
            |mut region| {
                // Raw assign the private memory inputs
                for (i, &value) in self.memory.iter().enumerate() {
                    // I think there will always be (0, 0) in the table so we index starting from 1
                    let idx = Value::known(F::from(i as u64 + 1));
                    raw_assign_advice(&mut region, config.memory[0], i, idx);
                    raw_assign_advice(&mut region, config.memory[1], i, Value::known(value));
                }
                self.cpu.assign_raw(
                    &(config.cpu.basic_gates[0].clone(), config.cpu.max_rows),
                    &mut region,
                );
                self.ram.assign_raw(&config.copy, &mut region);
                self.cpu.copy_manager.assign_raw(&config.cpu.constants, &mut region);
                Ok(())
            },
        )
    }
}

#[test]
fn test_ram_mock() {
    let k = 5u32;
    const CYCLES: usize = 50;
    let mut rng = StdRng::seed_from_u64(0);
    let mem_len = 16usize;
    let memory: Vec<_> = (0..mem_len).map(|_| Fr::random(&mut rng)).collect();
    let ptrs = [(); CYCLES].map(|_| rng.gen_range(0..memory.len()));
    let usable_rows = 2usize.pow(k) - 11; // guess
    let copy_columns = CYCLES / usable_rows + 1;
    let params = RAMConfigParams::default();
    let mut circuit = RAMCircuit::new(memory, ptrs, params, false);
    circuit.compute();
    // auto-configuration stuff
    let num_advice = circuit.cpu.total_advice() / usable_rows + 1;
    circuit.params.cpu = FlexGateConfigParams {
        k: k as usize,
        num_advice_per_phase: vec![num_advice],
        num_fixed: 1,
    };
    circuit.params.copy_columns = copy_columns;
    MockProver::run(k, &circuit, vec![]).unwrap().assert_satisfied();
}

#[test]
fn test_ram_prover() {
    let k = 10u32;
    const CYCLES: usize = 2000;

    let mut rng = StdRng::seed_from_u64(0);
    let mem_len = 500;

    let memory = vec![Fr::ZERO; mem_len];
    let ptrs = [0; CYCLES];

    let usable_rows = 2usize.pow(k) - 11; // guess
    let copy_columns = CYCLES / usable_rows + 1;
    let params = RAMConfigParams::default();
    let mut circuit = RAMCircuit::new(memory, ptrs, params, false);
    circuit.compute();
    let num_advice = circuit.cpu.total_advice() / usable_rows + 1;
    circuit.params.cpu = FlexGateConfigParams {
        k: k as usize,
        num_advice_per_phase: vec![num_advice],
        num_fixed: 1,
    };
    circuit.params.copy_columns = copy_columns;

    let params = gen_srs(k);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let circuit_params = circuit.params();
    let break_points = circuit.cpu.break_points.borrow().clone().unwrap();
    drop(circuit);

    let memory: Vec<_> = (0..mem_len).map(|_| Fr::random(&mut rng)).collect();
    let ptrs = [(); CYCLES].map(|_| rng.gen_range(0..memory.len()));
    let mut circuit = RAMCircuit::new(memory, ptrs, circuit_params, true);
    *circuit.cpu.break_points.borrow_mut() = Some(break_points);
    circuit.compute();

    let proof = gen_proof(&params, &pk, circuit);
    check_proof(&params, pk.get_vk(), &proof, true);
}
