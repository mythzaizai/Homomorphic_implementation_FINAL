#include <iostream>
#include <vector>
#include <cmath>
#include "FINAL.h"

using namespace std;


// Function to encrypt an integer into a vector of encrypted bits
vector<Ctxt_LWE> encrypt_integer(SchemeLWE& s, int num, int bits) {
    vector<Ctxt_LWE> ctxt_vector(bits);
    for (int i = 0; i < bits; ++i) {
        s.encrypt(ctxt_vector[i], (num >> i) & 1);
    }
    return ctxt_vector; 
}

// Function to decrypt a vector of encrypted bits into an integer
int decrypt_integer(SchemeLWE& s, const vector<Ctxt_LWE>& ctxt_vector) {
    int num = 0;
    int bits = ctxt_vector.size();
    for (int i = 0; i < bits; ++i) {
        int bit = s.decrypt(ctxt_vector[i]);
        num |= (bit << i);
    }
    // Handle sign extension if necessary
    if (num & (1 << (bits - 1))) {
        num |= ~((1 << bits) - 1);
    }
    return num;
}


vector<Ctxt_LWE> homomorphic_add(SchemeLWE& s, const vector<Ctxt_LWE>& a, const vector<Ctxt_LWE>& b) {
    int bits1 = a.size();
    int bits2 = b.size();
    int max_bits = max(bits1, bits2);

    // Extend a and b to the same length by adding zero bits if necessary
    vector<Ctxt_LWE> extended_a(max_bits);
    vector<Ctxt_LWE> extended_b(max_bits);
    Ctxt_LWE zero;
    s.encrypt(zero, 0);

    for (int i = 0; i < max_bits; ++i) {
        extended_a[i] = (i < bits1) ? a[i] : zero;
        extended_b[i] = (i < bits2) ? b[i] : zero;
    }

    // Initialize carry to 0
    vector<Ctxt_LWE> sum(max_bits);
    Ctxt_LWE carry;
    s.encrypt(carry, 0);

    // Perform addition bit by bit
    for (int i = 0; i < max_bits; ++i) {
        Ctxt_LWE temp_sum, temp_carry1, temp_carry2;

        s.xor_gate(temp_sum, extended_a[i], extended_b[i]);
        s.xor_gate(sum[i], temp_sum, carry);

        s.and_gate(temp_carry1, extended_a[i], extended_b[i]);
        s.and_gate(temp_carry2, temp_sum, carry);

        s.or_gate(carry, temp_carry1, temp_carry2);
    }

    return sum;
}


vector<Ctxt_LWE> homomorphic_sub(SchemeLWE& s, const vector<Ctxt_LWE>& a, const vector<Ctxt_LWE>& b) {
    int bits1 = a.size();
    int bits2 = b.size();
    int max_bits = max(bits1, bits2);

    // Extend a and b to the same length by adding zero bits if necessary
    vector<Ctxt_LWE> extended_a(max_bits);
    vector<Ctxt_LWE> extended_b(max_bits);
    Ctxt_LWE zero;
    s.encrypt(zero, 0);

    for (int i = 0; i < max_bits; ++i) {
        extended_a[i] = (i < bits1) ? a[i] : zero;
        extended_b[i] = (i < bits2) ? b[i] : zero;
    }

    // Compute the two's complement of b
    vector<Ctxt_LWE> b_complement(max_bits);

    // Invert each bit of b to get one's complement
    for (int i = 0; i < max_bits; ++i) {
        s.not_gate(b_complement[i], extended_b[i]);
    }

    // Prepare to add 1 (this is the second step of two's complement)
    vector<Ctxt_LWE> one(max_bits);
    s.encrypt(one[0], 1);
    for (int i = 1; i < max_bits; ++i) {
        s.encrypt(one[i], 0);
    }

    // Compute b_twos_complement = b_complement + 1
    vector<Ctxt_LWE> b_twos_complement(max_bits);
    Ctxt_LWE carry;
    s.encrypt(carry, 0);

    s.xor_gate(b_twos_complement[0], b_complement[0], one[0]);
    s.and_gate(carry, b_complement[0], one[0]);

    for (int i = 1; i < max_bits; ++i) {
        Ctxt_LWE temp_sum;
        s.xor_gate(temp_sum, b_complement[i], one[i]);
        s.xor_gate(b_twos_complement[i], temp_sum, carry);

        Ctxt_LWE carry_temp1, carry_temp2;
        s.and_gate(carry_temp1, b_complement[i], one[i]);
        s.and_gate(carry_temp2, temp_sum, carry);
        s.or_gate(carry, carry_temp1, carry_temp2);
    }

    // Now compute a + b_twos_complement
    vector<Ctxt_LWE> result(max_bits);
    s.encrypt(carry, 0);
    for (int i = 0; i < max_bits; ++i) {
        Ctxt_LWE temp_sum;
        s.xor_gate(temp_sum, extended_a[i], b_twos_complement[i]);
        s.xor_gate(result[i], temp_sum, carry);

        Ctxt_LWE carry_temp1, carry_temp2;
        s.and_gate(carry_temp1, extended_a[i], b_twos_complement[i]);
        s.and_gate(carry_temp2, temp_sum, carry);
        s.or_gate(carry, carry_temp1, carry_temp2);
    }

    return result;
}

vector<Ctxt_LWE> homomorphic_mult(SchemeLWE& s, const vector<Ctxt_LWE>& a, const vector<Ctxt_LWE>& b) {
    int bits1 = a.size();
    int bits2 = b.size();
    int result_bits = bits1 + bits2;
    vector<Ctxt_LWE> result(result_bits);

    // Initialize result bits to 0
    Ctxt_LWE zero;
    s.encrypt(zero, 0);
    for (int i = 0; i < result_bits; ++i) {
        result[i] = zero;
    }

    // Perform multiplication using shift and add algorithm
    for (int i = 0; i < bits2; ++i) {
        vector<Ctxt_LWE> temp_product(result_bits);

        // Initialize temp_product to zeros
        for (int j = 0; j < result_bits; ++j) {
            temp_product[j] = zero;
        }

        // Multiply a by the i-th bit of b
        for (int j = 0; j < bits1; ++j) {
            Ctxt_LWE temp_bit;
            s.and_gate(temp_bit, a[j], b[i]);

            int k = j + i;
            if (k < result_bits) {
                temp_product[k] = temp_bit;
            }
        }

        // Homomorphic addition: result = result + temp_product
        result = homomorphic_add(s, result, temp_product);
    }

    return result;
}

//////////////////////

// if qbit=1 then x else y : (qbit ∧ x[i]) ∨ (¬qbit ∧ y[i])
Ctxt_LWE homomorphic_mux_bit(SchemeLWE& s, const Ctxt_LWE& control, const Ctxt_LWE& x, const Ctxt_LWE& y) {
    Ctxt_LWE not_control;
    s.not_gate(not_control, control);

    Ctxt_LWE x_and_control, y_and_not_control, result;
    s.and_gate(x_and_control, x, control);
    s.and_gate(y_and_not_control, y, not_control);
    s.or_gate(result, x_and_control, y_and_not_control);

    return result;
}

// MUX for a vector of bits (x: test, y: new_remainder)
vector<Ctxt_LWE> homomorphic_mux(SchemeLWE& s, const Ctxt_LWE& control, const vector<Ctxt_LWE>& x, const vector<Ctxt_LWE>& y) {
    int n = (int)x.size();
    vector<Ctxt_LWE> result(n);
    for (int i = 0; i < n; ++i) {
        result[i] = homomorphic_mux_bit(s, control, x[i], y[i]);    // result[i] = (qbit ∧ x[i]) ∨ (¬qbit ∧ y[i])
    }
    return result;
}

// 新插入的位元當作最低位元；原本最高位元會被捨棄(因為溢位)
vector<Ctxt_LWE> homomorphic_shift_left(SchemeLWE& s, const vector<Ctxt_LWE>& v, const Ctxt_LWE& new_bit) {
    int n = (int)v.size();
    vector<Ctxt_LWE> shifted(n);
    shifted[0] = new_bit;
    for (int i = 1; i < n; ++i) {
        shifted[i] = v[i - 1];
    }
    return shifted;
}

// 取得最高位元
Ctxt_LWE get_sign_bit(const vector<Ctxt_LWE>& v) {
    return v[v.size() - 1];
}


struct DivResult {
    vector<Ctxt_LWE> quotient;
    vector<Ctxt_LWE> remainder;
};
// 使用 Restoring Division 演算法
// dividend / divisor = quotient
// 不回傳餘數(remainder)，但會在過程中計算。
DivResult homomorphic_div(SchemeLWE& s, const vector<Ctxt_LWE>& dividend, const vector<Ctxt_LWE>& divisor) {
    int n = (int)dividend.size();
    // quotient 和 remainder 都是 n bits
    vector<Ctxt_LWE> quotient(n), remainder(n);
    Ctxt_LWE zero;
    s.encrypt(zero, 0);

    // 初始化 quotient, remainder = 0
    for (int i = 0; i < n; ++i) {
        quotient[i] = zero;
        remainder[i] = zero;
    }

    // dividend : 5 (1,0,1) (0, 1, 0) (0,0,1)
    // remainder : (0,0,0) (0, 0, 1) (0,1,0)
    // divisor: 2



    for (int i = n - 1; i >= 0; --i) {
        // 將 remainder 左移一位，並將 dividend 的第 i 位加入 remainder 的最低位元
        vector<Ctxt_LWE> new_remainder = homomorphic_shift_left(s, remainder, dividend[i]);

        // test = new_remainder - divisor
        vector<Ctxt_LWE> test = homomorphic_sub(s, new_remainder, divisor);

        // 查看 test 的 sign bit (最高位元)
        // 若為 0 表示 test >=0，否則 test <0，檢查是否overflow
        Ctxt_LWE test_sign = get_sign_bit(test);

        // qbit = NOT test_sign (test_sign=0 -> qbit=1表示可減除, test_sign=1 -> qbit=0表示不可減除)
        Ctxt_LWE qbit;
        s.not_gate(qbit, test_sign);

        // 若 test >=0 (減成功)，則 remainder = test (更新新值)，否則 remainder = new_remainder (保持原值)
        remainder = homomorphic_mux(s, qbit, test, new_remainder);

        quotient[i] = qbit;
    }



    DivResult div_result;
    div_result.quotient = quotient;
    div_result.remainder = remainder;
    return div_result;
}

//////////////////////

// Euclid's algorithm

// 檢查同態加密的 bit 向量是否全為 0
// 若是全 0，回傳 1 (true)；若非全 0，回傳 0 (false)。
Ctxt_LWE homomorphic_is_zero(SchemeLWE& s, const vector<Ctxt_LWE>& v) {
    Ctxt_LWE accum;
    s.encrypt(accum, 0);  // 先令 accum = 0

    for (const auto& bit : v) {
        Ctxt_LWE tmp;
        // accum = accum OR bit
        s.or_gate(tmp, accum, bit);
        accum = tmp;
    }
    // accum == 1 => 表示「至少有一個 bit 為 1」 => 整體不為 0
    // accum == 0 => 表示「所有 bit 都是 0」 => 整體為 0

    // is_zero = NOT accum
    Ctxt_LWE is_zero;
    s.not_gate(is_zero, accum);  
    return is_zero;   // is_zero == 1 => v 全為 0
}

vector<Ctxt_LWE> homomorphic_gcd(SchemeLWE& s, const vector<Ctxt_LWE>& A, const vector<Ctxt_LWE>& B, int max_iter) {
    vector<Ctxt_LWE> a = A;
    vector<Ctxt_LWE> b = B;

    for (int i = 0; i < max_iter; i++) {
        // (1) 檢查 b 是否為 0
        Ctxt_LWE b_is_zero = homomorphic_is_zero(s, b);

        // (2) 計算 a mod b (div_res.remainder)
        DivResult div_res = homomorphic_div(s, a, b);
        vector<Ctxt_LWE> remainder = div_res.remainder;

        // 為安全，若 b=0 => remainder = b (0)，以免無意義的除法結果汙染
        vector<Ctxt_LWE> safe_remainder = homomorphic_mux(s, b_is_zero, b, remainder);

        // (3) 歐幾里得演算法交換步驟
        //     temp = b;  b = remainder;  a = temp;
        //     MUX: b=0，則不更新(保持原值)
        vector<Ctxt_LWE> new_b = homomorphic_mux(s, b_is_zero, b, safe_remainder);
        vector<Ctxt_LWE> new_a = homomorphic_mux(s, b_is_zero, a, b);

        a = new_a;
        b = new_b;
    }

    return a;
}

//////////////////////

int main() {

    SchemeLWE s;

    const int MAX_BITS = 8;

    int num1 = 33, num2 = 6, num3 = 2;

    // Encrypt num1 and num2
    vector<Ctxt_LWE> a = encrypt_integer(s, num1, MAX_BITS);
    vector<Ctxt_LWE> b = encrypt_integer(s, num2, MAX_BITS);
    vector<Ctxt_LWE> c = encrypt_integer(s, num3, MAX_BITS);


    // // test val
    // Ctxt_LWE zero_1, zero_2;
    // s.encrypt(zero_1, 0);
    // s.encrypt(zero_2, 0);
    // for (int val : zero_1.a) {
    //     std::cout << val << " ";
    // }
    // cout << endl << endl;
    // for (int val : zero_2.a) {
    //     std::cout << val << " ";
    // }
    // return 0;

    // Homomorphic Addition
    vector<Ctxt_LWE> sum = homomorphic_add(s, a, b);
    int add_result = decrypt_integer(s, sum);
    cout << "[INFO] Result of " << num1 << " + " << num2 << ": " << add_result << endl;

    // Homomorphic Subtraction
    vector<Ctxt_LWE> diff = homomorphic_sub(s, a, b);
    int sub_result = decrypt_integer(s, diff);
    cout << "[INFO] Result of " << num1 << " - " << num2 << ": " << sub_result << endl;

    // Homomorphic Multiplication
    vector<Ctxt_LWE> product = homomorphic_mult(s, a, b);
    int mult_result = decrypt_integer(s, product);
    cout << "[INFO] Result of " << num1 << " * " << num2 << ": " << mult_result << endl;

    // Homomorphic Division
    DivResult div_result = homomorphic_div(s, a, b);
    int q_div_result = decrypt_integer(s, div_result.quotient);
    int r_div_result = decrypt_integer(s, div_result.remainder);

    cout << "[INFO] Result of " << num1 << " / " << num2 << ": " << q_div_result << endl;
    cout << "[INFO] Result of " << num1 << " mod " << num2 << ": " << r_div_result << endl;


    // Other operation
    vector<Ctxt_LWE> r_c; 
    r_c = homomorphic_mult(s, a, c);
    r_c = homomorphic_add(s, r_c, b);
    r_c = homomorphic_sub(s, r_c, a);
    int r_p = decrypt_integer(s, r_c);
    cout << "[INFO] Result of " << num1 << " * " << num3 << " + " << num2 << " - " << num1 << ": " << r_p << endl;


    // Euclid's algorithm
    vector<Ctxt_LWE> gcd_result = homomorphic_gcd(s, a, b, /*max_iter=*/ 8);
    int gcd_val = decrypt_integer(s, gcd_result);
    cout << "[INFO] GCD(" << num1 << ", " << num2 << ") = " << gcd_val << endl;



    return 0;
}
