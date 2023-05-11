
use crate::utils::ScalarField;
use crate::QuantumCell;

// Ground truth functions

//  Flex Gate Ground Truths

pub fn add_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() + *inputs[1].value()
}

pub fn sub_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() - *inputs[1].value()
}

pub fn neg_ground_truth<F: ScalarField>(input: QuantumCell<F>) -> F {
    -(*input.value())
}

pub fn mul_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value()
}

pub fn mul_add_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value() + *inputs[2].value()
}

pub fn mul_not_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * (F::one() - *inputs[1].value())
}

pub fn div_unsafe_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    inputs[0].value().invert().unwrap() * *inputs[1].value()
}

pub fn inner_product_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> F {
    inputs.0.iter().zip(inputs.1.iter()).fold(F::zero(),|acc, (a, b)| acc + (*a.value() * *b.value()))    
}

pub fn inner_product_left_last_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> (F, F) {
    let product = inner_product_ground_truth(inputs);
    let last = *inputs.0.last().unwrap().value();
    (product, last)
}

pub fn inner_product_with_sums_ground_truth<F: ScalarField>(input: &(Vec<QuantumCell<F>>, Vec<QuantumCell<F>>)) -> Vec<F> {
    let (a, b) = &input;
    let mut result = Vec::new();
    let mut sum = F::zero();
    // TODO: convert to fold
    for (ai, bi) in a.iter().zip(b) {
        let product = *ai.value() * *bi.value();
        sum += product;
        result.push(sum);
    }
    result
}

pub fn sum_products_with_coeff_and_var_ground_truth<F: ScalarField>(input: &(Vec<(F, QuantumCell<F>, QuantumCell<F>)>, QuantumCell<F>)) -> F {
    let expected = input.0.iter().fold(F::zero(), |acc, (coeff, cell1, cell2)| {
        acc + *coeff * *cell1.value() * *cell2.value()
    }) + *input.1.value();
    expected
}

pub fn and_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    *inputs[0].value() * *inputs[1].value()
}

pub fn not_ground_truth<F: ScalarField>(a: &QuantumCell<F>) -> F {
    F::one() - *a.value()
}

pub fn select_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    (*inputs[0].value() *  *inputs[2].value()) +  (*inputs[1].value() *( *inputs[2].value() - F::one()))
}

pub fn or_and_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    let bc_val = *inputs[1].value() * inputs[2].value();
    bc_val + inputs[0].value() - bc_val * inputs[0].value()
}

pub fn idx_to_indicator_ground_truth<F: ScalarField>(inputs: (QuantumCell<F>, usize)) -> Vec<F> {
    let (idx, size) = inputs;
    let mut indicator = vec![F::zero(); size];
    let mut idx_value = size + 1;
    for i in 0..size as u64 {
        if F::from(i) == *idx.value() {
            idx_value = i as usize;
            break;
        }
    }
    if idx_value < size {
        indicator[idx_value] = F::one();
    }
    indicator
}

pub fn select_by_indicator_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let mut idx_value = inputs.0.len() + 1;
    let mut indicator = vec![F::zero(); inputs.0.len()];
    for i in 0..inputs.0.len() as u64{
        if F::from(i) == *inputs.1.value() {
            idx_value = i as usize;
            break;
        }
    }
    if idx_value < inputs.0.len() {
        indicator[idx_value] = F::one();
    }
    // take cross product of indicator and inputs.0
    inputs.0.iter().zip(indicator.iter()).fold(F::zero(),|acc, (a, b)| acc + (*a.value() * *b))
}

pub fn select_from_idx_ground_truth<F: ScalarField>(inputs: &(Vec<QuantumCell<F>>, QuantumCell<F>)) -> F {
    let idx = inputs.1.value();
    // Since F does not implement From<u64>, we have to iterate and find the matching index
    for i in 0..inputs.0.len() as u64 {
        if F::from(i) == *idx {
            return *inputs.0[i as usize].value();
        }
    }
    F::zero()
}

pub fn is_zero_ground_truth<F: ScalarField>(x: F) -> F {
    if x.is_zero().into() { F::one() } else { F::zero() }
}

pub fn is_equal_ground_truth<F: ScalarField>(inputs: &[QuantumCell<F>]) -> F {
    if inputs[0].value() == inputs[1].value() {
        F::one()
    } else {
        F::zero()
    }
}

pub fn lagrange_eval_ground_truth<F: ScalarField>(inputs: &[F]) -> (F, F) {
    let x1 = inputs[0];
    let x2 = inputs[1];
    let y1 = inputs[2];
    let quotient = (y1 - x1).invert().unwrap() * (x2 - x1);
    let y2 = quotient * (x2 - x1) + x1;
    (quotient, y2)
}

pub fn get_field_element_ground_truth<F: ScalarField>(n: u64) -> F {
    F::from(n)
}

// Range Chip Ground Truths

pub fn is_less_than_ground_truth<F: ScalarField>(inputs: (F, F)) -> F {
    if inputs.0 < inputs.1 {
        F::one()
    } else {
        F::zero()
    }
}

pub fn is_less_than_safe_ground_truth<F: ScalarField>(inputs: (F, u64)) -> F {
    if inputs.0 < F::from(inputs.1) {
        F::one()
    } else {
        F::zero()
    }
}

pub fn div_mod_ground_truth<F: ScalarField>(inputs: (F, u64)) -> (F, F) {
    let dividend = inputs.0;
    let divisor = F::from(inputs.1);
    let quotient = dividend.invert().unwrap() * divisor;
    let remainder = dividend - (quotient * divisor);
    (quotient, remainder)
}

pub fn get_last_bit_ground_truth<F: ScalarField>(inputs: (F, usize)) -> F {
    let bits = inputs.0.to_repr().as_ref()[0] >> (inputs.1 - 1);
    F::from(u64::from(bits & 1))
}
