//! Arithmetics of the Galois Field needed for the BCH code in the fuzzy commitment

// Declaration of the constants of the field GF(2^6)

// Generator of the field : polynomial alpha = X "=" 0b000010 "=" 2
const ALPHA : usize = 2; 

const GROUP_EXPONENT : usize = 6; 
// #(GF(2^6))
const CARDINALITY : usize = 1<<GROUP_EXPONENT ; 
// w(alpha) : order of the generator alpha
const ORDER : usize = CARDINALITY - 1; 
// p(X) = X^6 + X + 1
const PRIMITIVE_POLYNOMIAL : usize = 0b1000011; 

/// Generate the logarithmic and anti-log tables for faster multiplication
// N.B. : log_table[0] = 0 but it isn't useful as the log of 0 does not exists
const fn generate_log_exp_table() -> ([usize; ORDER  * 2], [usize; ORDER + 1]){
    let mut exp_table = [0; ORDER * 2];
    let mut log_table = [0; ORDER + 1];

    let mut i : usize = 0;
    let mut x : usize = 1;
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
    return (exp_table, log_table)
}