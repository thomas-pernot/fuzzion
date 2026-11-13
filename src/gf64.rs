//! Arithmetics of the Galois Field needed for the BCH code in the fuzzy commitment

// #(GF(2^6))
const CARDINALITY: usize = 1 << 6;
// w(alpha) : order of the generator alpha
const ORDER: usize = CARDINALITY - 1;
// p(X) = X^6 + X + 1
const PRIMITIVE_POLYNOMIAL: usize = 0b1000011;

/// Generate the logarithmic and anti-log tables for faster multiplication
// N.B. : log_table[0] = 0 but it isn't useful as the log of 0 does not exists
const fn generate_log_exp_table() -> ([usize; ORDER * 2], [usize; ORDER + 1]) {
    let mut exp_table = [0; ORDER * 2];
    let mut log_table = [0; ORDER + 1];

    let mut i: usize = 0;
    let mut x: usize = 1;
    // We go over all the possible exponentiations of alpha (from 0 to 62)
    while i < ORDER {
        // Update of the tables in both ways
        exp_table[i] = x;
        log_table[x] = i;
        // Multiplication of the current exponent by alpha=X for the next computation (alpha^i = alpha^(i-1).alpha)
        // Equivalent to a multiplication by 2, i.e. a bit-shift
        x <<= 1;
        // Handling of overflow after the bit-shift (i.e. x<<1 > 63)
        if x >= CARDINALITY {
            x ^= PRIMITIVE_POLYNOMIAL; // Reduction modulo the primitive polynomial
        }
        // Incrementation of i for the while loop
        i += 1;
    }
    while i < ORDER * 2 {
        // Copy the first half of the table in the second part of it
        // alpha^order = alpha^0, alpha^order+i = alpha^i
        // Needed in case the sum of the logs reach up to 2*(ORDER-1)
        exp_table[i] = exp_table[i - ORDER];
        // Incrementation of i for the while loop
        i += 1;
    }
    return (exp_table, log_table);
}

pub const EXP_LOG_TABLES: ([usize; ORDER * 2], [usize; ORDER + 1]) = generate_log_exp_table();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test that all values in the exp_table are different between them
    fn test_exp_all_values_diff() {
        let exp_table = EXP_LOG_TABLES.0;
        for i in 0..ORDER {
            for j in i+1..ORDER {
                assert_ne!(
                    exp_table[i], exp_table[j],
                    "Two identical values found in the anti-log table :\n
                    {} (index {i})\n
                    {} (index {j})\n",
                    exp_table[i], exp_table[j]
                );
            }
        }
    }

    #[test]
    /// Test that none of the values in the exp_table are equal to 0
    fn test_exp_all_values_not_null() {
        let exp_table = EXP_LOG_TABLES.0;
        for (i, val) in exp_table.iter().enumerate() {
            assert_ne!(*val, 0, "Value at index {i} equals {val}");
        }
    }

    #[test]
    /// Test that alpha^order=alpha^0 and alpha^order+i = alpha^i for all i < order
    fn test_exp_cyclic() {
        let exp_table = EXP_LOG_TABLES.0;
        for i in ORDER..exp_table.len() {
            assert_eq!(
                exp_table[i - ORDER],
                exp_table[i],
                "Different values found at {i} ({}) and {} ({})", exp_table[i], i-ORDER, exp_table[i-ORDER]
            );
        }
    }

    #[test]
    // Test that the back and forth between the two tables work
    fn test_back_and_forth() {
        let exp_table= EXP_LOG_TABLES.0;
        let log_table = EXP_LOG_TABLES.1;
        for i in 1..=ORDER {
            // We do not check the case i=0 since log(0) is not defined
            assert_eq!(
                exp_table[log_table[i]], i,
                "Back and forth gave a wrong value at index {i} :\n
                log_table[{i}] = {}\n
                exp_table[log_table[{i}] = {}",
                log_table[i], exp_table[log_table[i]]
            );
        }
        for i in 0..ORDER {
            assert_eq!(
                log_table[exp_table[i]], i,
                "Back and forth gave a wrong value at index {i} :\n
                exp_table[{i}] = {}\n
                log_table[exp_table[{i}] = {}",
                exp_table[i], log_table[exp_table[i]]
            );
        }
    }
}
