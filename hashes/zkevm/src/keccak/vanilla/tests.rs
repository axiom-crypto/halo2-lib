use super::{witness::*, *};
use crate::halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::bn256::Fr,
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::Circuit,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2_base::{
    halo2_proofs::halo2curves::ff::FromUniformBytes, utils::value_to_option, SKIP_FIRST_PASS,
};
use hex::FromHex;
use rand_core::OsRng;
use sha3::{Digest, Keccak256};
use test_case::test_case;

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    verify_output: bool,
    _marker: PhantomData<F>,
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = KeccakCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = KeccakConfigParams;

    fn params(&self) -> Self::Params {
        self.config
    }

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure_with_params(meta: &mut ConstraintSystem<F>, params: Self::Params) -> Self::Config {
        // MockProver complains if you only have columns in SecondPhase, so let's just make an empty column in FirstPhase
        meta.advice_column();

        KeccakCircuitConfig::new(meta, params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!()
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let params = config.parameters;
        config.load_aux_tables(&mut layouter, params.k)?;
        let mut first_pass = SKIP_FIRST_PASS;
        layouter.assign_region(
            || "keccak circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let (witness, _) = multi_keccak(
                    &self.inputs,
                    self.num_rows.map(|nr| get_keccak_capacity(nr, params.rows_per_round)),
                    params,
                );
                let assigned_rows = config.assign(&mut region, &witness);
                if self.verify_output {
                    self.verify_output_witnesses(&assigned_rows);
                    self.verify_input_witnesses(&assigned_rows);
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> KeccakCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(
        config: KeccakConfigParams,
        num_rows: Option<usize>,
        inputs: Vec<Vec<u8>>,
        verify_output: bool,
    ) -> Self {
        KeccakCircuit { config, inputs, num_rows, _marker: PhantomData, verify_output }
    }

    fn verify_output_witnesses(&self, assigned_rows: &[KeccakAssignedRow<F>]) {
        let mut input_offset = 0;
        // only look at last row in each round
        // first round is dummy, so ignore
        // only look at last round per absorb of RATE_IN_BITS
        for assigned_row in
            assigned_rows.iter().step_by(self.config.rows_per_round).step_by(NUM_ROUNDS + 1).skip(1)
        {
            let KeccakAssignedRow { is_final, hash_lo, hash_hi, .. } = assigned_row.clone();
            let is_final_val = extract_value(is_final).ne(&F::ZERO);
            let hash_lo_val = extract_u128(hash_lo);
            let hash_hi_val = extract_u128(hash_hi);

            if input_offset < self.inputs.len() && is_final_val {
                // out is in big endian.
                let out = Keccak256::digest(&self.inputs[input_offset]);
                let lo = u128::from_be_bytes(out[16..].try_into().unwrap());
                let hi = u128::from_be_bytes(out[..16].try_into().unwrap());
                assert_eq!(lo, hash_lo_val);
                assert_eq!(hi, hash_hi_val);
                input_offset += 1;
            }
        }
    }

    fn verify_input_witnesses(&self, assigned_rows: &[KeccakAssignedRow<F>]) {
        let rows_per_round = self.config.rows_per_round;
        let mut input_offset = 0;
        let mut input_byte_offset = 0;
        // first round is dummy, so ignore
        for absorb_chunk in &assigned_rows.chunks(rows_per_round).skip(1).chunks(NUM_ROUNDS + 1) {
            let mut absorbed = false;
            for (round_idx, assigned_rows) in absorb_chunk.enumerate() {
                for (row_idx, assigned_row) in assigned_rows.iter().enumerate() {
                    let KeccakAssignedRow { is_final, word_value, bytes_left, .. } =
                        assigned_row.clone();
                    let is_final_val = extract_value(is_final).ne(&F::ZERO);
                    let word_value_val = extract_u128(word_value);
                    let bytes_left_val = extract_u128(bytes_left);
                    // Padded inputs - all empty.
                    if input_offset >= self.inputs.len() {
                        assert_eq!(word_value_val, 0);
                        assert_eq!(bytes_left_val, 0);
                        continue;
                    }
                    let input_len = self.inputs[input_offset].len();
                    if round_idx == NUM_ROUNDS && row_idx == 0 && is_final_val {
                        absorbed = true;
                    }
                    if row_idx == 0 {
                        assert_eq!(bytes_left_val, input_len as u128 - input_byte_offset as u128);
                        // Only these rows could contain inputs.
                        let end = if round_idx < NUM_WORDS_TO_ABSORB {
                            std::cmp::min(input_byte_offset + NUM_BYTES_PER_WORD, input_len)
                        } else {
                            input_byte_offset
                        };
                        let mut expected_val_le_bytes =
                            self.inputs[input_offset][input_byte_offset..end].to_vec().clone();
                        expected_val_le_bytes.resize(NUM_BYTES_PER_WORD, 0);
                        assert_eq!(
                            word_value_val,
                            u64::from_le_bytes(expected_val_le_bytes.try_into().unwrap()) as u128,
                        );
                        input_byte_offset = end;
                    }
                }
            }
            if absorbed {
                input_offset += 1;
                input_byte_offset = 0;
            }
        }
    }
}

fn verify<F: Field + Ord + FromUniformBytes<64>>(
    config: KeccakConfigParams,
    inputs: Vec<Vec<u8>>,
    _success: bool,
) {
    let k = config.k;
    let circuit = KeccakCircuit::new(config, Some(2usize.pow(k) - 109), inputs, true);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

fn extract_value<F: Field>(assigned_value: KeccakAssignedValue<F>) -> F {
    #[cfg(feature = "halo2-axiom")]
    let assigned = **value_to_option(assigned_value.value()).unwrap();
    #[cfg(not(feature = "halo2-axiom"))]
    let assigned = *value_to_option(assigned_value.value()).unwrap();
    match assigned {
        halo2_base::halo2_proofs::plonk::Assigned::Zero => F::ZERO,
        halo2_base::halo2_proofs::plonk::Assigned::Trivial(f) => f,
        _ => panic!("value should be trival"),
    }
}

fn extract_u128<F: Field>(assigned_value: KeccakAssignedValue<F>) -> u128 {
    let le_bytes = extract_value(assigned_value).to_bytes_le();
    let hi = u128::from_le_bytes(le_bytes[16..].try_into().unwrap());
    assert_eq!(hi, 0);
    u128::from_le_bytes(le_bytes[..16].try_into().unwrap())
}

#[test_case(14, 28; "k: 14, rows_per_round: 28")]
#[test_case(12, 5; "k: 12, rows_per_round: 5")]
fn packed_multi_keccak_simple(k: u32, rows_per_round: usize) {
    let _ = env_logger::builder().is_test(true).try_init();
    {
        // First input is empty.
        let inputs = vec![
            vec![],
            (0u8..1).collect::<Vec<_>>(),
            (0u8..135).collect::<Vec<_>>(),
            (0u8..136).collect::<Vec<_>>(),
            (0u8..200).collect::<Vec<_>>(),
        ];
        verify::<Fr>(KeccakConfigParams { k, rows_per_round }, inputs, true);
    }
    {
        // First input is not empty.
        let inputs = vec![
            (0u8..200).collect::<Vec<_>>(),
            vec![],
            (0u8..1).collect::<Vec<_>>(),
            (0u8..135).collect::<Vec<_>>(),
            (0u8..136).collect::<Vec<_>>(),
        ];
        verify::<Fr>(KeccakConfigParams { k, rows_per_round }, inputs, true);
    }
}

#[test_case(14, 25 ; "k: 14, rows_per_round: 25")]
#[test_case(18, 9 ; "k: 18, rows_per_round: 9")]
fn packed_multi_keccak_prover(k: u32, rows_per_round: usize) {
    let _ = env_logger::builder().is_test(true).try_init();

    let params = ParamsKZG::<Bn256>::setup(k, OsRng);

    let inputs = vec![
        (0u8..200).collect::<Vec<_>>(),
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit::new(
        KeccakConfigParams { k, rows_per_round },
        Some(2usize.pow(k)),
        inputs,
        false,
    );

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    let verifier_params: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    let start = std::time::Instant::now();
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
    .expect("proof generation should not fail");
    let proof = transcript.finalize();
    dbg!(start.elapsed());

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&params);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(&verifier_params, pk.get_vk(), strategy, &[&[]], &mut verifier_transcript)
    .expect("failed to verify bench circuit");
}

// Keccak Known Answer Test (KAT) vectors from https://keccak.team/obsolete/KeccakKAT-3.zip.
// Only selecting a small subset for now (add more later)
// KAT includes inputs at the bit level; we only include the ones that are bytes
#[test]
fn test_vanilla_keccak_kat_vectors() {
    let _ = env_logger::builder().is_test(true).try_init();

    // input, output, Len in bits
    let test_vectors = vec![
            ("", "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470"), // ShortMsgKAT_256 Len = 0
            ("CC", "EEAD6DBFC7340A56CAEDC044696A168870549A6A7F6F56961E84A54BD9970B8A"), // ShortMsgKAT_256 Len = 8
            ("B55C10EAE0EC684C16D13463F29291BF26C82E2FA0422A99C71DB4AF14DD9C7F33EDA52FD73D017CC0F2DBE734D831F0D820D06D5F89DACC485739144F8CFD4799223B1AFF9031A105CB6A029BA71E6E5867D85A554991C38DF3C9EF8C1E1E9A7630BE61CAABCA69280C399C1FB7A12D12AEFC", "0347901965D3635005E75A1095695CCA050BC9ED2D440C0372A31B348514A889"), // ShortMsgKAT_256 Len = 920
            ("2EDC282FFB90B97118DD03AAA03B145F363905E3CBD2D50ECD692B37BF000185C651D3E9726C690D3773EC1E48510E42B17742B0B0377E7DE6B8F55E00A8A4DB4740CEE6DB0830529DD19617501DC1E9359AA3BCF147E0A76B3AB70C4984C13E339E6806BB35E683AF8527093670859F3D8A0FC7D493BCBA6BB12B5F65E71E705CA5D6C948D66ED3D730B26DB395B3447737C26FAD089AA0AD0E306CB28BF0ACF106F89AF3745F0EC72D534968CCA543CD2CA50C94B1456743254E358C1317C07A07BF2B0ECA438A709367FAFC89A57239028FC5FECFD53B8EF958EF10EE0608B7F5CB9923AD97058EC067700CC746C127A61EE3", "DD1D2A92B3F3F3902F064365838E1F5F3468730C343E2974E7A9ECFCD84AA6DB"), // ShortMsgKAT_256 Len = 1952,
            ("724627916C50338643E6996F07877EAFD96BDF01DA7E991D4155B9BE1295EA7D21C9391F4C4A41C75F77E5D27389253393725F1427F57914B273AB862B9E31DABCE506E558720520D33352D119F699E784F9E548FF91BC35CA147042128709820D69A8287EA3257857615EB0321270E94B84F446942765CE882B191FAEE7E1C87E0F0BD4E0CD8A927703524B559B769CA4ECE1F6DBF313FDCF67C572EC4185C1A88E86EC11B6454B371980020F19633B6B95BD280E4FBCB0161E1A82470320CEC6ECFA25AC73D09F1536F286D3F9DACAFB2CD1D0CE72D64D197F5C7520B3CCB2FD74EB72664BA93853EF41EABF52F015DD591500D018DD162815CC993595B195", "EA0E416C0F7B4F11E3F00479FDDF954F2539E5E557753BD546F69EE375A5DE29"), // LongMsgKAT_256 Len = 2048
            ("6E1CADFB2A14C5FFB1DD69919C0124ED1B9A414B2BEA1E5E422D53B022BDD13A9C88E162972EBB9852330006B13C5B2F2AFBE754AB7BACF12479D4558D19DDBB1A6289387B3AC084981DF335330D1570850B97203DBA5F20CF7FF21775367A8401B6EBE5B822ED16C39383232003ABC412B0CE0DD7C7DA064E4BB73E8C58F222A1512D5FE6D947316E02F8AA87E7AA7A3AA1C299D92E6414AE3B927DB8FF708AC86A09B24E1884743BC34067BB0412453B4A6A6509504B550F53D518E4BCC3D9C1EFDB33DA2EACCB84C9F1CAEC81057A8508F423B25DB5500E5FC86AB3B5EB10D6D0BF033A716DDE55B09FD53451BBEA644217AE1EF91FAD2B5DCC6515249C96EE7EABFD12F1EF65256BD1CFF2087DABF2F69AD1FFB9CF3BC8CA437C7F18B6095BC08D65DF99CC7F657C418D8EB109FDC91A13DC20A438941726EF24F9738B6552751A320C4EA9C8D7E8E8592A3B69D30A419C55FB6CB0850989C029AAAE66305E2C14530B39EAA86EA3BA2A7DECF4B2848B01FAA8AA91F2440B7CC4334F63061CE78AA1589BEFA38B194711697AE3AADCB15C9FBF06743315E2F97F1A8B52236ACB444069550C2345F4ED12E5B8E881CDD472E803E5DCE63AE485C2713F81BC307F25AC74D39BAF7E3BC5E7617465C2B9C309CB0AC0A570A7E46C6116B2242E1C54F456F6589E20B1C0925BF1CD5F9344E01F63B5BA9D4671ABBF920C7ED32937A074C33836F0E019DFB6B35D865312C6058DFDAFF844C8D58B75071523E79DFBAB2EA37479DF12C474584F4FF40F00F92C6BADA025CE4DF8FAF0AFB2CE75C07773907CA288167D6B011599C3DE0FFF16C1161D31DF1C1DDE217CB574ED5A33751759F8ED2B1E6979C5088B940926B9155C9D250B479948C20ACB5578DC02C97593F646CC5C558A6A0F3D8D273258887CCFF259197CB1A7380622E371FD2EB5376225EC04F9ED1D1F2F08FA2376DB5B790E73086F581064ED1C5F47E989E955D77716B50FB64B853388FBA01DAC2CEAE99642341F2DA64C56BEFC4789C051E5EB79B063F2F084DB4491C3C5AA7B4BCF7DD7A1D7CED1554FA67DCA1F9515746A237547A4A1D22ACF649FA1ED3B9BB52BDE0C6996620F8CFDB293F8BACAD02BCE428363D0BB3D391469461D212769048219220A7ED39D1F9157DFEA3B4394CA8F5F612D9AC162BF0B961BFBC157E5F863CE659EB235CF98E8444BC8C7880BDDCD0B3B389AAA89D5E05F84D0649EEBACAB4F1C75352E89F0E9D91E4ACA264493A50D2F4AED66BD13650D1F18E7199E931C78AEB763E903807499F1CD99AF81276B615BE8EC709B039584B2B57445B014F6162577F3548329FD288B0800F936FC5EA1A412E3142E609FC8E39988CA53DF4D8FB5B5FB5F42C0A01648946AC6864CFB0E92856345B08E5DF0D235261E44CFE776456B40AEF0AC1A0DFA2FE639486666C05EA196B0C1A9D346435E03965E6139B1CE10129F8A53745F80100A94AE04D996C13AC14CF2713E39DFBB19A936CF3861318BD749B1FB82F40D73D714E406CBEB3D920EA037B7DE566455CCA51980F0F53A762D5BF8A4DBB55AAC0EDDB4B1F2AED2AA3D01449D34A57FDE4329E7FF3F6BECE4456207A4225218EE9F174C2DE0FF51CEAF2A07CF84F03D1DF316331E3E725C5421356C40ED25D5ABF9D24C4570FED618CA41000455DBD759E32E2BF0B6C5E61297C20F752C3042394CE840C70943C451DD5598EB0E4953CE26E833E5AF64FC1007C04456D19F87E45636F456B7DC9D31E757622E2739573342DE75497AE181AAE7A5425756C8E2A7EEF918E5C6A968AEFE92E8B261BBFE936B19F9E69A3C90094096DAE896450E1505ED5828EE2A7F0EA3A28E6EC47C0AF711823E7689166EA07ECA00FFC493131D65F93A4E1D03E0354AFC2115CFB8D23DAE8C6F96891031B23226B8BC82F1A73DAA5BB740FC8CC36C0975BEFA0C7895A9BBC261EDB7FD384103968F7A18353D5FE56274E4515768E4353046C785267DE01E816A2873F97AAD3AB4D7234EBFD9832716F43BE8245CF0B4408BA0F0F764CE9D24947AB6ABDD9879F24FCFF10078F5894B0D64F6A8D3EA3DD92A0C38609D3C14FDC0A44064D501926BE84BF8034F1D7A8C5F382E6989BFFA2109D4FBC56D1F091E8B6FABFF04D21BB19656929D19DECB8E8291E6AE5537A169874E0FE9890DFF11FFD159AD23D749FB9E8B676E2C31313C16D1EFA06F4D7BC191280A4EE63049FCEF23042B20303AECDD412A526D7A53F760A089FBDF13F361586F0DCA76BB928EDB41931D11F679619F948A6A9E8DBA919327769006303C6EF841438A7255C806242E2E7FF4621BB0F8AFA0B4A248EAD1A1E946F3E826FBFBBF8013CE5CC814E20FEF21FA5DB19EC7FF0B06C592247B27E500EB4705E6C37D41D09E83CB0A618008CA1AAAE8A215171D817659063C2FA385CFA3C1078D5C2B28CE7312876A276773821BE145785DFF24BBB24D590678158A61EA49F2BE56FDAC8CE7F94B05D62F15ADD351E5930FD4F31B3E7401D5C0FF7FC845B165FB6ABAFD4788A8B0615FEC91092B34B710A68DA518631622BA2AAE5D19010D307E565A161E64A4319A6B261FB2F6A90533997B1AEC32EF89CF1F232696E213DAFE4DBEB1CF1D5BBD12E5FF2EBB2809184E37CD9A0E58A4E0AF099493E6D8CC98B05A2F040A7E39515038F6EE21FC25F8D459A327B83EC1A28A234237ACD52465506942646AC248EC96EBBA6E1B092475F7ADAE4D35E009FD338613C7D4C12E381847310A10E6F02C02392FC32084FBE939689BC6518BE27AF7842DEEA8043828E3DFFE3BBAC4794CA0CC78699722709F2E4B0EAE7287DEB06A27B462423EC3F0DF227ACF589043292685F2C0E73203E8588B62554FF19D6260C7FE48DF301509D33BE0D8B31D3F658C921EF7F55449FF3887D91BFB894116DF57206098E8C5835B", "3C79A3BD824542C20AF71F21D6C28DF2213A041F77DD79A328A0078123954E7B"), // LongMsgKAT_256 Len = 16664
            ("7ADC0B6693E61C269F278E6944A5A2D8300981E40022F839AC644387BFAC9086650085C2CDC585FEA47B9D2E52D65A2B29A7DC370401EF5D60DD0D21F9E2B90FAE919319B14B8C5565B0423CEFB827D5F1203302A9D01523498A4DB10374", "4CC2AFF141987F4C2E683FA2DE30042BACDCD06087D7A7B014996E9CFEAA58CE"), // ShortMsgKAT_256 Len = 752
        ];

    let mut inputs = vec![];
    for (input, output) in test_vectors {
        let input = Vec::from_hex(input).unwrap();
        let output = Vec::from_hex(output).unwrap();
        // test against native sha3 implementation because that's what we will test circuit against
        let native_out = Keccak256::digest(&input);
        assert_eq!(&output[..], &native_out[..]);
        inputs.push(input);
    }
    verify::<Fr>(KeccakConfigParams { k: 12, rows_per_round: 5 }, inputs, true);
}
