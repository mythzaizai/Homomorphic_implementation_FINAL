#include <iostream>
#include <cassert>
#include <time.h>
#include <cstdint>
#include <stdexcept>
#include <chrono>
#include <limits.h>
#include <NTL/ZZX.h>
#include "FINAL.h"

using namespace std;
using namespace NTL;


int homomorphic_add(SchemeLWE& s, int num1, int num2) {
    // Calculate the number of bits needed in one line
    int bits = ceil(log2(abs(num1) + abs(num2) + 1)) + 2; // +1 for sign, +1 for possible carry

    // Initialize encrypted bit vectors
    vector<Ctxt_LWE> a(bits), b(bits), sum(bits);

    // Encrypt each bit of num1 and num2
    for (int i = 0; i < bits; ++i) {
        s.encrypt(a[i], (num1 >> i) & 1);
        s.encrypt(b[i], (num2 >> i) & 1);
    }

    // Initialize carry to 0
    Ctxt_LWE carry;
    s.encrypt(carry, 0);

    // Perform addition bit by bit
    for (int i = 0; i < bits; ++i) {
        Ctxt_LWE temp_sum, temp_carry1, temp_carry2;

        s.xor_gate(temp_sum, a[i], b[i]);
        s.xor_gate(sum[i], temp_sum, carry);

        s.and_gate(temp_carry1, a[i], b[i]);
        s.and_gate(temp_carry2, temp_sum, carry);

        s.or_gate(carry, temp_carry1, temp_carry2);
    }

    // Decrypt and convert the binary result back to an integer
    int final_result = 0;
    for (int i = 0; i < bits; ++i) {
        final_result |= (s.decrypt(sum[i]) << i);
    }

    // Handle sign extension: if the most significant bit is 1, it's a negative number
    if (final_result & (1 << (bits - 1))) {
        final_result |= ~((1 << bits) - 1);  // Extend the sign bit to the entire integer
    }

    return final_result;
}



int homomorphic_sub(SchemeLWE& s, int num1, int num2) {
    // Determine the number of bits needed, adding 1 for possible borrow and sign bit
    int bits = max(ceil(log2(abs(num1) + 1)), ceil(log2(abs(num2) + 1))) + 2; // Add 1 bit for sign

    // Initialize encrypted bit vectors
    vector<Ctxt_LWE> a(bits), b(bits), result(bits);

    // Encrypt each bit of num1 and num2
    for (int i = 0; i < bits; ++i) {
        s.encrypt(a[i], (num1 >> i) & 1);  // Encrypt bit i of num1
        s.encrypt(b[i], (num2 >> i) & 1);  // Encrypt bit i of num2
    }

    // Compute the two's complement of num2
    vector<Ctxt_LWE> b_complement(bits), one(bits);
    
    // Invert each bit of num2 to get one's complement
    for (int i = 0; i < bits; ++i) {
        s.not_gate(b_complement[i], b[i]);  // Invert bit i of num2
    }

    // Prepare to add 1 (this is the second step of two's complement)
    s.encrypt(one[0], 1);  // Set the least significant bit to 1 (for adding 1)
    for (int i = 1; i < bits; ++i) {
        s.encrypt(one[i], 0);  // Set the other bits to 0
    }

    // Compute the two's complement: b_complement + 1
    vector<Ctxt_LWE> b_twos_complement(bits);
    Ctxt_LWE carry;  // Used for handling carry in addition
    s.encrypt(carry, 0);  // Initialize carry to 0

    // Add the least significant bit
    s.xor_gate(b_twos_complement[0], b_complement[0], one[0]);
    s.and_gate(carry, b_complement[0], one[0]);

    // Perform addition for the remaining bits (b_complement + 1)
    for (int i = 1; i < bits; ++i) {
        Ctxt_LWE temp_sum;
        s.xor_gate(temp_sum, b_complement[i], one[i]);
        s.xor_gate(b_twos_complement[i], temp_sum, carry);

        Ctxt_LWE carry_temp1, carry_temp2;
        s.and_gate(carry_temp1, b_complement[i], one[i]);
        s.and_gate(carry_temp2, temp_sum, carry);
        s.or_gate(carry, carry_temp1, carry_temp2);
    }

    // Now perform a + b_twos_complement
    vector<Ctxt_LWE> sum(bits);
    s.encrypt(carry, 0);  // Initialize carry for the addition

    // Add the least significant bit
    s.xor_gate(sum[0], a[0], b_twos_complement[0]);
    s.and_gate(carry, a[0], b_twos_complement[0]);

    // Perform addition for the remaining bits
    for (int i = 1; i < bits; ++i) {
        Ctxt_LWE temp_sum;
        s.xor_gate(temp_sum, a[i], b_twos_complement[i]);
        s.xor_gate(sum[i], temp_sum, carry);

        Ctxt_LWE carry_temp1, carry_temp2;
        s.and_gate(carry_temp1, a[i], b_twos_complement[i]);
        s.and_gate(carry_temp2, temp_sum, carry);
        s.or_gate(carry, carry_temp1, carry_temp2);
    }

    // Decrypt and convert the binary result back to an integer
    int final_result = 0;
    for (int i = 0; i < bits; ++i) {
        final_result |= (s.decrypt(sum[i]) << i);
    }

    // Handle sign extension: if the most significant bit is 1, it's a negative number
    if (final_result & (1 << (bits - 1))) {
        final_result |= ~((1 << bits) - 1);  // Extend the sign bit to the entire integer
    }

    return final_result;
}


int homomorphic_mult(SchemeLWE& s, int num1, int num2) {
    // Determine the number of bits needed, including sign bits
    int bits1 = ceil(log2(abs(num1) + 1)) + 1; // Number of bits for num1
    int bits2 = ceil(log2(abs(num2) + 1)) + 1; // Number of bits for num2
    int result_bits = bits1 + bits2; // Maximum possible bits for the result

    // Initialize encrypted bit vectors
    vector<Ctxt_LWE> a(bits1), b(bits2), result(result_bits);

    // Encrypt each bit of num1 and num2
    for (int i = 0; i < bits1; ++i) {
        s.encrypt(a[i], (num1 >> i) & 1);  // Encrypt bit i of num1
    }
    for (int i = 0; i < bits2; ++i) {
        s.encrypt(b[i], (num2 >> i) & 1);  // Encrypt bit i of num2
    }

    // Initialize result bits to 0
    for (int i = 0; i < result_bits; ++i) {
        s.encrypt(result[i], 0);  // Encrypt 0 as initial value for result
    }

    // Perform multiplication using shift and add algorithm
    for (int i = 0; i < bits2; ++i) {
        // If the ith bit of num2 is 1, perform shifted addition
        if (s.decrypt(b[i]) == 1) {
            vector<Ctxt_LWE> shifted_a(result_bits);
            // Left shift a by i bits
            for (int j = 0; j < i; ++j) {
                s.encrypt(shifted_a[j], 0);  // Zero padding for lower bits due to shift
            }
            for (int j = 0; j < bits1; ++j) {
                shifted_a[j + i] = a[j];  // Left-shifted a
            }
            for (int j = bits1 + i; j < result_bits; ++j) {
                s.encrypt(shifted_a[j], 0);  // Zero padding for higher bits
            }

            // Homomorphic addition: result += shifted_a
            Ctxt_LWE carry;
            s.encrypt(carry, 0);  // Initialize carry to 0
            vector<Ctxt_LWE> temp_result(result_bits);

            for (int k = 0; k < result_bits; ++k) {
                Ctxt_LWE sum1, carry_out, temp_carry1, temp_carry2;
                s.xor_gate(sum1, result[k], shifted_a[k]);  // Partial sum
                s.xor_gate(temp_result[k], sum1, carry);    // Current bit result

                s.and_gate(temp_carry1, result[k], shifted_a[k]);   // Carry computation
                s.and_gate(temp_carry2, sum1, carry);
                s.or_gate(carry_out, temp_carry1, temp_carry2);

                carry = carry_out;  // Update carry
            }
            result = temp_result;  // Update result
        }
    }

    // Decrypt and convert the binary result back to an integer
    int final_result = 0;
    for (int i = 0; i < result_bits; ++i) {
        int bit = s.decrypt(result[i]);
        final_result |= (bit << i);
    }

    // Handle sign extension (if the most significant bit is 1, it's negative)
    if (final_result & (1 << (result_bits - 1))) {
        final_result |= ~((1 << result_bits) - 1);  // Sign extension
    }

    return final_result;
}


int homomorphic_div(SchemeLWE& s, int num1, int num2) {
    if (num2 == 0) {
        throw invalid_argument("Division by zero.");
    }

    // Encrypt the numerator and denominator
    int quotient = 0, remainder = num1;

    // Iteratively subtract num2 from the numerator to compute the quotient
    while (remainder >= num2) {
        remainder = homomorphic_sub(s, remainder, num2);
        quotient++;
    }

    return quotient;
}


int homomorphic_mod(SchemeLWE& s, int num1, int num2) {
    if (num2 == 0) {
        throw invalid_argument("Division by zero.");
    }

    // Encrypt the numerator and denominator
    int quotient = 0, remainder = num1;

    // Iteratively subtract num2 from the numerator to compute the quotient
    while (remainder >= num2) {
        remainder = homomorphic_sub(s, remainder, num2);
        quotient++;
    }

    return remainder;
}


int main() {
    // Initialize the homomorphic encryption scheme
    SchemeLWE s;

    // Test numbers for addition, subtraction, multiplication, and division
    int num1 = 27, num2 = 6;

    // addition
    int add_result = homomorphic_add(s, num1, num2);
    cout << "[INFO] Result of " << num1 << " + " << num2 << ": " << add_result << endl;

    // subtraction
    int sub_result = homomorphic_sub(s, num1, num2);
    cout << "[INFO] Result of " << num1 << " - " << num2 << ": " << sub_result << endl;

    // multiplication
    int mult_result = homomorphic_mult(s, num1, num2);
    cout << "[INFO] Result of " << num1 << " * " << num2 << ": " << mult_result << endl;

    // division
    int div_result = homomorphic_div(s, num1, num2);
    cout << "[INFO] Result of " << num1 << " / " << num2 << ": " << div_result << endl;

    // mod
    int mod_result = homomorphic_mod(s, num1, num2);
    cout << "[INFO] Result of " << num1 << " % " << num2 << ": " << mod_result << endl;

    return 0;
}