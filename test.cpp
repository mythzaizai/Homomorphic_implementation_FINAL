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

void test_params()
{
    {
        Param param(LWE);
        cout << "Ciphertext modulus of the base scheme (LWE): " << param.q_base << endl;
        cout << "Dimension of the base scheme (LWE): " << param.n << endl;
        cout << "Ciphertext modulus for bootstrapping (LWE): " << q_boot << endl;
        cout << "Polynomial modulus (LWE): " << Param::get_def_poly() << endl;
        assert(param.l_ksk == int(ceil(log(double(param.q_base))/log(double(Param::B_ksk)))));
        cout << "Decomposition length for key-switching (LWE): " << param.l_ksk << endl;
        cout << "Decomposition bases for key-switching (LWE): " << Param::B_ksk << endl;
        cout << "Dimension for bootstrapping (LWE): " << Param::N << endl;
        cout << "Decomposition bases for bootstrapping (LWE): ";
        for (const auto &v: param.B_bsk) cout << v << ' ';
        cout << endl;
        cout << "Delta (LWE): " << param.delta_base << endl;
        cout << "Half Delta (LWE): " << param.half_delta_base << endl;
    }
    {
        Param param(NTRU);
        cout << "Ciphertext modulus of the base scheme (MNTRU): " << param.q_base << endl;
        cout << "Dimension of the base scheme (NTRU): " << param.n << endl;
        cout << "Ciphertext modulus for bootstrapping (NTRU): " << q_boot << endl;
        cout << "Polynomial modulus (NTRU): " << Param::get_def_poly() << endl;
        assert(param.l_ksk == int(ceil(log(double(param.q_base))/log(double(Param::B_ksk)))));
        cout << "Decomposition length for key-switching (MNTRU): " << param.l_ksk << endl;
        cout << "Decomposition bases for key-switching (MNTRU): " << Param::B_ksk << endl;
        cout << "Dimension for bootstrapping (MNTRU): " << Param::N << endl;
        cout << "Decomposition bases for bootstrapping (MNTRU): ";
        for (const auto &v: param.B_bsk) cout << v << ' ';
        cout << endl;
        cout << "Decomposition lengths for bootstrapping (MNTRU): ";
        for (int i = 0; i < Param::B_bsk_size; i++) 
        {
            assert(param.l_bsk[i] == int(ceil(log(double(q_boot))/log(double(param.B_bsk[i])))));
            cout << param.l_bsk[i] << ' ';
        }
        cout << endl;
        cout << "Decomposition lengths for bootstrapping (MNTRU): ";
        for (int i = 0; i < Param::B_bsk_size; i++) 
        {
            assert(param.l_bsk[i] == int(ceil(log(double(q_boot))/log(double(param.B_bsk[i])))));
            cout << param.l_bsk[i] << ' ';
        }
        cout << endl;
        cout << "Delta (MNTRU): " << param.delta_base << endl;
        cout << "Half Delta (MNTRU): " << param.half_delta_base << endl;

        {
            assert(0L == mod_q_boot(0L));
            assert(1L == mod_q_boot(1L));
            assert(0L == mod_q_boot(q_boot));
            assert(half_q_boot == mod_q_boot(half_q_boot));
            assert(-half_q_boot == mod_q_boot(-half_q_boot));
            cout << "MODULO REDUCTION IS OK" << endl;
        }
    }
    
    cout << "Plaintext modulus: " << Param::t << endl;
    cout << endl;
    cout << "PARAMS ARE OK" << endl;

    {
        vector<int> res;
        decompose(res, 0, 2, 3);
        assert(res.size() == 3);
        for (auto iter=res.begin(); iter < res.end(); iter++)
            assert(0L == *iter);
    }
    {
        vector<int> res;
        decompose(res, 1, 2, 3);
        assert(res.size() == 3);
        assert(res[0] == 1);
        for (auto iter=res.begin()+1; iter < res.end(); iter++)
            assert(0L == *iter);
    }
    {
        vector<int> res;
        decompose(res, 2, 3, 3);
        assert(res.size() == 3);
        assert(res[0] == -1 && res[1] == 1 && res[2] == 0);
    }
    {
        vector<int> res;
        decompose(res, 2, 4, 3);
        assert(res.size() == 3);
        assert(res[0] == 2 && res[1] == 0 && res[2] == 0);
        decompose(res, 3, 4, 3);
        assert(res.size() == 3);
        assert(res[0] == -1 && res[1] == 1 && res[2] == 0);
    }
    {
        vector<int> res;
        try
        {
            decompose(res, 14, 3, 3);
            assert(false);
        }
        catch (overflow_error)
        {
            assert(true);
        }
    }
    {
        vector<int> res;
        try
        {
            decompose(res, -14, 3, 3);
            assert(false);
        }
        catch (overflow_error)
        {
            assert(true);
        }
    }
    {
        vector<int> res;
        decompose(res, 13, 3, 3);
        assert(res.size() == 3);
        assert(res[0] == 1 && res[1] == 1 && res[2] == 1);
        decompose(res, -13, 3, 3);
        assert(res.size() == 3);
        assert(res[0] == -1 && res[1] == -1 && res[2] == -1);
    }


    cout << "DECOMPOSITION IS OK" << endl;

    
}

void test_sampler()
{
    int N = Param::N;

    Param pLWE(LWE);
    Param pNTRU(NTRU);
    for (int run = 0; run < 1; run++)
    {
        //cout << "Run: " << run+1 << endl;
        {
            vector<int> vec(pNTRU.n, 0L);
            Sampler::get_ternary_vector(vec);
            
            assert(vec.size() == pNTRU.n);
            for (int i = 0; i < pNTRU.n; i++)
            {
                assert((vec[i]==0) || (vec[i]==-1) || (vec[i]==1) );
            }
        }

        {
            vector<int> vec(N,0L);
            Sampler::get_ternary_vector(vec);
            
            assert(vec.size() == N);
            for (int i = 0; i < N; i++)
            {
                assert((vec[i]==0) || (vec[i]==-1) || (vec[i]==1) );
            }
        }

        {
            vector<int> vec(N,0L);
            Sampler::get_binary_vector(vec);
            
            assert(vec.size() == N);
            for (int i = 0; i < N; i++)
            {
                assert((vec[i]==0) || (vec[i]==1) );
            }
        }

        {
            int n = pLWE.n;
            vector<vector<int>> mat(n, vector<int>(N,0L));
            Sampler::get_ternary_matrix(mat);
            
            assert(mat.size() == n && mat[0].size() == N);
            for (int i = 0; i < n; i++)
            {
                vector<int>& row = mat[i];
                for (int j = 0; j < N; j++)
                    assert((row[j]==0) || (row[j]==-1) || (row[j]==1) );
            }
        }

        {
            int n = pLWE.n;
            vector<int> vec(n, 0L);
            double st_dev = 4.0;
            Sampler::get_gaussian_vector(vec, st_dev);
            
            assert(vec.size() == n);
            for (int i = 0; i < n; i++)
            {
                assert(conv<double>(abs(vec[i])) < 6*st_dev);
            }
        }

        {
            int n = pNTRU.n;
            vector<vector<int>> mat(n, vector<int>(N,0L));
            double st_dev = 4.0;
            Sampler::get_gaussian_matrix(mat, st_dev);
            
            assert(mat.size() == n && mat[0].size() == N);
            for (int i = 0; i < n; i++)
            {
                vector<int>& row = mat[i];
                for (int j = 0; j < N; j++)
                    assert(conv<double>(abs(row[j])) < 6*st_dev);
            }
        }

        {
            vector<int> vec_inv(N,0L);
            vector<int> vec(N,0L);
            Sampler s(pNTRU);
            s.get_invertible_vector(vec, vec_inv, 4, 1);
            
            assert(vec.size() == N && vec_inv.size() == N);
            assert((vec[0]==1) || (vec[0]==-3) || (vec[0]==5) );
            for (int i = 1; i < N; i++)
            {
                assert((vec[i]==0) || (vec[i]==-4) || (vec[i]==4));
            }
        }

        {
            int n = pLWE.n;
            vector<vector<int>> mat_inv(n, vector<int>(n,0L));
            vector<vector<int>> mat(n, vector<int>(n,0L));
            Sampler s(pLWE);
            s.get_invertible_matrix(mat, mat_inv, 5, 1);
            
            assert(mat.size() == n && mat[0].size() == n 
                && mat_inv.size() == n && mat_inv[0].size() == n);
            for (int i = 0; i < n; i++)
                assert((mat[i][i]==1) || (mat[i][i]==-4) || (mat[i][i]==6) );
            
            for (int i = 0; i < n; i++)
                for (int j = 0; (j < n) && (j != i); j++)
                {
                    assert((mat[i][j]==0) || (mat[i][j]==-5) || (mat[i][j]==5) );
                }
        }
    }
    cout << "SAMPLER IS OK" << endl;
}

enum GateType {NAND, AND, OR, XOR, NOT};

void test_ntruhe_gate_helper(int in1, int in2, const SchemeNTRU& s, GateType g)
{
    float avg_time = 0.0;
    int N_TESTS = (g == NOT ? 30 : 100);
    for (int i = 0; i < N_TESTS; i++)
    {
        Ctxt_NTRU ct_res, ct1, ct2;
        s.encrypt(ct1, in1);
        s.encrypt(ct2, in2);
        
        if (g == NAND)
        {
            auto start = clock();
            s.nand_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            cout << "NAND output: " << output << endl;
            assert(output == !(in1 & in2));
        }
        else if (g == AND) {
            auto start = clock();
            s.and_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "AND output: " << output << endl;
            assert(output == (in1 & in2));
        }
        else if (g == OR) {
            auto start = clock();
            s.or_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "OR output: " << output << endl;
            assert(output == (in1 | in2));
        }
        else if (g == XOR) {
            auto start = clock();
            s.xor_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "XOR output: " << output << endl;
            assert(output == (in1 ^ in2));
        }
        else if (g == NOT) {
            auto start = clock();
            s.not_gate(ct_res, ct1);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

//            cout << ".... NOT output: " << output << endl;
            assert(output == (1 - in1));
        }

    }
    cout << "Avg. time: " << avg_time/N_TESTS << endl;
}

void test_ntru_gate(SchemeNTRU& s, GateType g)
{
    test_ntruhe_gate_helper(0, 0, s, g);
    test_ntruhe_gate_helper(0, 1, s, g);
    test_ntruhe_gate_helper(1, 0, s, g);
    test_ntruhe_gate_helper(1, 1, s, g);
}

void test_ntruhe_nand(SchemeNTRU& s)
{
    GateType g = NAND;

    test_ntru_gate(s, g);

    cout << "NAND IS OK" << endl;
}

void test_ntruhe_and(SchemeNTRU& s)
{
    GateType g = AND;
    test_ntru_gate(s, g);
    cout << "AND IS OK" << endl;
}

void test_ntruhe_or(SchemeNTRU& s)
{
    GateType g = OR;
    test_ntru_gate(s, g);
    cout << "OR IS OK" << endl;
}

void test_ntruhe_xor(SchemeNTRU& s)
{
    GateType g = XOR;
    test_ntru_gate(s, g);
    cout << "XOR IS OK" << endl;
}

void test_ntruhe_not(SchemeNTRU& s)
{
    GateType g = NOT;
    for(int i = 0; i < 5; i++){
        int bit = binary_sampler(rand_engine);
        test_ntruhe_gate_helper(bit, 0, s, g);
    }
    cout << "NOT GATE IS OK" << endl;
}


void test_ntruhe_gate_composition_helper(SchemeNTRU& s, GateType g)
{
    float avg_time = 0.0;
    int N_TESTS = 100;

    int in1, in2, exp_out;
    in1 = binary_sampler(rand_engine);
    exp_out = in1;

    Ctxt_NTRU ct_res, ct;
    s.encrypt(ct_res, in1);
    for (int i = 0; i < N_TESTS; i++)
    {
        in2 = binary_sampler(rand_engine);
        s.encrypt(ct, in2);
        if (g == NAND)
        {
            auto start = clock();
            s.nand_gate(ct_res, ct_res, ct);// ct_res should encrypt NAND(exp_out, in2)
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = !(exp_out & in2); // exp_out = NAND(exp_out, in2)
        }
        else if (g == AND) {
            auto start = clock();
            s.and_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out & in2); // exp_out = AND(exp_out, in2)
        }
        else if (g == OR) {
            auto start = clock();
            s.or_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out | in2); // exp_out = OR(exp_out, in2)
        }
        else if (g == XOR) {
            auto start = clock();
            s.xor_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out ^ in2); // exp_out = XOR(exp_out, in2)
        }
        else if (g == NOT) {
            auto start = clock();
            s.not_gate(ct_res, ct_res);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (1 - exp_out); // exp_out = NOT(exp_out)
        }

        int output = s.decrypt(ct_res);
        assert(output == exp_out);
    }
    cout << "Avg. time: " << avg_time/N_TESTS << endl;
}

void test_ntruhe_composition_of_gates(SchemeNTRU& s)
{
    test_ntruhe_gate_composition_helper(s, NAND);
    cout << "COMPOSING NAND IS OK" << endl;

    test_ntruhe_gate_composition_helper(s, AND);
    cout << "COMPOSING AND IS OK" << endl;

    test_ntruhe_gate_composition_helper(s, OR);
    cout << "COMPOSING OR IS OK" << endl;

    test_ntruhe_gate_composition_helper(s, XOR);
    cout << "COMPOSING XOR IS OK" << endl;

    test_ntruhe_gate_composition_helper(s, NOT);
    cout << "COMPOSING NOT GATE IS OK" << endl;
}


// ----- LWE tests

void test_lwehe_gate_helper(int in1, int in2, SchemeLWE& s, GateType g)
{
    float avg_time = 0.0;
    for (int i = 0; i < 100; i++)
    {
        Ctxt_LWE ct_res, ct1, ct2;
        s.encrypt(ct1, in1);
        s.encrypt(ct2, in2);
        
        if (g == NAND)
        {
            auto start = clock();
            s.nand_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "NAND output: " << output << endl;
            assert(output == !(in1 & in2));
        }
        else if (g == AND) {
            auto start = clock();
            s.and_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "AND output: " << output << endl;
            assert(output == (in1 & in2));
        }
        else if (g == OR) {
            auto start = clock();
            s.or_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "OR output: " << output << endl;
            assert(output == (in1 | in2));
        }
        else if (g == XOR) {
            auto start = clock();
            s.xor_gate(ct_res, ct1, ct2);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

            //cout << "OR output: " << output << endl;
            assert(output == (in1 ^ in2));
        }
        else if (g == NOT) {
            auto start = clock();
            s.not_gate(ct_res, ct1);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;

            int output = s.decrypt(ct_res);

//            cout << "NOT output: " << output << endl;
            assert(output == (1 - in1));
        }



    }
    cout << "Avg. time: " << avg_time/100.0 << endl;
}

void test_lwe_gate(SchemeLWE& s, GateType g)
{
    test_lwehe_gate_helper(0, 0, s, g);
    test_lwehe_gate_helper(0, 1, s, g);
    test_lwehe_gate_helper(1, 0, s, g);
    test_lwehe_gate_helper(1, 1, s, g);
}

void test_lwehe_nand(SchemeLWE& s)
{
    GateType g = NAND;
    test_lwe_gate(s, g);
    cout << "NAND IS OK" << endl;
}

void test_lwehe_and(SchemeLWE& s)
{
    GateType g = AND;
    test_lwe_gate(s, g);
    cout << "AND IS OK" << endl;
}

void test_lwehe_or(SchemeLWE& s)
{
    GateType g = OR;
    test_lwe_gate(s, g);
    cout << "OR IS OK" << endl;
}

void test_lwehe_xor(SchemeLWE& s)
{
    GateType g = XOR;
    test_lwe_gate(s, g);
    cout << "XOR IS OK" << endl;
}

void test_lwehe_not(SchemeLWE& s)
{
    GateType g = NOT;
    for(int i = 0; i < 4; i++){
        int bit = binary_sampler(rand_engine);
        test_lwehe_gate_helper(bit, 0, s, g);
    }

    cout << "NOT GATE IS OK" << endl;
}


void test_lwehe_gate_composition_helper(SchemeLWE& s, GateType g)
{
    float avg_time = 0.0;
    int N_TESTS = 110;

    int in1, in2, exp_out;
    in1 = binary_sampler(rand_engine);
    exp_out = in1;

    Ctxt_LWE ct_res, ct;
    s.encrypt(ct_res, in1);
    for (int i = 0; i < N_TESTS; i++)
    {
        in2 = binary_sampler(rand_engine);
        s.encrypt(ct, in2);
        if (g == NAND)
        {
            auto start = clock();
            s.nand_gate(ct_res, ct_res, ct);// ct_res should encrypt NAND(exp_out, in2)
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = !(exp_out & in2); // exp_out = NAND(exp_out, in2)
            //cout << "NAND output: " << output << endl;
        }
        else if (g == AND) {
            auto start = clock();
            s.and_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out & in2); // exp_out = AND(exp_out, in2)
            //cout << "AND output: " << output << endl;
        }
        else if (g == OR) {
            auto start = clock();
            s.or_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out | in2); // exp_out = OR(exp_out, in2)
            //cout << "OR output: " << output << endl;
        }
        else if (g == XOR) {
            auto start = clock();
            s.xor_gate(ct_res, ct_res, ct);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (exp_out ^ in2); // exp_out = XOR(exp_out, in2)
            //cout << "XOR output: " << output << endl;
        }
        else if (g == NOT) {
            auto start = clock();
            s.not_gate(ct_res, ct_res);
            avg_time += float(clock()-start)/CLOCKS_PER_SEC;
            exp_out = (1 - exp_out); // exp_out = NOT(exp_out)
        }

        int output = s.decrypt(ct_res);
        assert(output == exp_out);
    }
    cout << "Avg. time: " << avg_time/N_TESTS << endl;
}

void test_lwehe_composition_of_gates(SchemeLWE& s)
{
    test_lwehe_gate_composition_helper(s, NAND);
    cout << "COMPOSING NAND IS OK" << endl;

    test_lwehe_gate_composition_helper(s, AND);
    cout << "COMPOSING AND IS OK" << endl;

    test_lwehe_gate_composition_helper(s, OR);
    cout << "COMPOSING OR IS OK" << endl;

    test_lwehe_gate_composition_helper(s, XOR);
    cout << "COMPOSING XOR IS OK" << endl;

    test_lwehe_gate_composition_helper(s, NOT);
    cout << "COMPOSING NOT GATE IS OK" << endl;
}



int main(){

    ///////////////////////////////////////////////
    //    Test basic homomorphic operations      //
    ///////////////////////////////////////////////

    // Input bits
    int b1 = 0;
    int b2 = 1;

    SchemeLWE s;

    // LWE ciphertexts
    Ctxt_LWE ct1, ct2, ct3, ct_or, ct_nand, ct_xor, ct_and, ct_not;

    // Encryption of bits
    s.encrypt(ct1, b1);
    s.encrypt(ct2, b2);

    // Computes AND
    s.and_gate(ct_and, ct1, ct2);
    assert(s.decrypt(ct_and) == 0);
    if(s.decrypt(ct_and) == 0){
        cout << "Computes AND -> PASSED" << endl;
    }

    // Computes NAND
    s.nand_gate(ct_nand, ct1, ct2);
    assert(s.decrypt(ct_nand) == 1);
    if(s.decrypt(ct_nand) == 1){
        cout << "Computes NAND -> PASSED" << endl;
    }

    // Computes OR
    s.or_gate(ct_or, ct1, ct2);
    assert(s.decrypt(ct_or) == 1);
    if(s.decrypt(ct_or) == 1){
        cout << "Computes OR -> PASSED" << endl;
    }

    // Computes XOR
    s.xor_gate(ct_xor, ct1, ct2);
    assert(s.decrypt(ct_xor) == 1);
    if(s.decrypt(ct_xor) == 1){
        cout << "Computes XOR -> PASSED" << endl;
    }

    // Computes NOT
    s.not_gate(ct_not, ct1);
    assert(s.decrypt(ct_not) == 1);
    if(s.decrypt(ct_not) == 1){
        cout << "Computes NOT -> PASSED" << endl;
    }

    /////////////////////////////////////////////////////
    //   Decimal plaintext homomorphic computation     // 
    /////////////////////////////////////////////////////

    cout << "[INFO] Decimal plaintext homomorphic computation" << endl; 

    cout << "[INFO] Addition..." << endl;

    // 3 -> 011
    int b1_2 = 0, b1_1 = 1, b1_0 = 1;
    // 4 -> 100
    int b2_2 = 1, b2_1 = 0, b2_0 = 0;

    Ctxt_LWE ct1_2, ct1_1, ct1_0;
    Ctxt_LWE ct2_2, ct2_1, ct2_0;

    s.encrypt(ct1_2, b1_2);
    s.encrypt(ct1_1, b1_1);
    s.encrypt(ct1_0, b1_0);

    s.encrypt(ct2_2, b2_2);
    s.encrypt(ct2_1, b2_1);
    s.encrypt(ct2_0, b2_0);


    Ctxt_LWE sum_0, sum_1, sum_2, carry_1, carry_2;

    s.xor_gate(sum_0, ct1_0, ct2_0);                    // sum_0 = b1_0 XOR b2_0
    s.and_gate(carry_1, ct1_0, ct2_0);                  // carry_1 = b1_0 AND b2_0

    Ctxt_LWE temp_sum_1;
    s.xor_gate(temp_sum_1, ct1_1, ct2_1);               // temp_sum_1 = b1_1 XOR b2_1
    s.xor_gate(sum_1, temp_sum_1, carry_1);             // sum_1 = temp_sum_1 XOR carry_1

    Ctxt_LWE carry_1_temp;
    s.and_gate(carry_1_temp, temp_sum_1, carry_1);

    Ctxt_LWE temp_or_1;
    s.and_gate(temp_or_1, ct1_1, ct2_1);
    s.or_gate(carry_2, temp_or_1, carry_1_temp);        // carry_2 = (b1_1 AND b2_1) OR (carry_1 AND temp_sum_1)

    Ctxt_LWE temp_sum_2;
    s.xor_gate(temp_sum_2, ct1_2, ct2_2);               // temp_sum_2 = b1_2 XOR b2_2
    s.xor_gate(sum_2, temp_sum_2, carry_2);             // sum_2 = temp_sum_2 XOR carry_2

    // decode each bits
    int result_0 = s.decrypt(sum_0);
    int result_1 = s.decrypt(sum_1);
    int result_2 = s.decrypt(sum_2);

    // binary to decimal
    int result = (result_2 << 2) + (result_1 << 1) + result_0;

    cout << "[INFO] Result of 3 + 4: " << result << endl;


    //------------------------------------------------------------------
    cout << "[INFO] Multiplication..." << endl;

    Ctxt_LWE prod_0, prod_1, prod_2, prod_3, prod_4, carry_1_mult, carry_2_mult, carry_3_mult;

    s.and_gate(prod_0, ct1_0, ct2_0); // prod_0 = b1_0 * b2_0

    Ctxt_LWE temp1, temp2, temp3, temp4, temp_sum, temp_and_mult;
    s.and_gate(temp1, ct1_1, ct2_0); // b1_1 * b2_0
    s.and_gate(temp2, ct1_0, ct2_1); // b1_0 * b2_1
    s.xor_gate(prod_1, temp1, temp2); // prod_1 = b1_1 * b2_0 XOR b1_0 * b2_1
    s.and_gate(carry_1_mult, temp1, temp2); // carry_1_mult = b1_1 * b2_0 AND b1_0 * b2_1

    s.and_gate(temp1, ct1_2, ct2_0); // b1_2 * b2_0
    s.and_gate(temp2, ct1_1, ct2_1); // b1_1 * b2_1
    s.and_gate(temp3, ct1_0, ct2_2); // b1_0 * b2_2

    s.xor_gate(temp_sum, temp1, temp2); // temp_sum = b1_2 * b2_0 XOR b1_1 * b2_1
    s.xor_gate(prod_2, temp_sum, carry_1_mult); // prod_2 = temp_sum XOR carry_1_mult
    s.xor_gate(prod_2, prod_2, temp3);

    s.and_gate(temp4, temp_sum, carry_1_mult); // temp4 = temp_sum AND carry_1_mult
    s.and_gate(temp_and_mult, temp1, temp3); // temp_and_mult = temp1 AND temp3
    s.or_gate(carry_2_mult, temp4, temp_and_mult); // carry_2_mult = temp4 OR temp_and_mult

    s.and_gate(temp1, ct1_2, ct2_1); // b1_2 * b2_1
    s.and_gate(temp2, ct1_1, ct2_2); // b1_1 * b2_2

    s.xor_gate(temp_sum, temp1, temp2); // temp_sum = b1_2 * b2_1 XOR b1_1 * b2_2
    s.xor_gate(prod_3, temp_sum, carry_2_mult); // prod_3 = temp_sum XOR carry_2_mult

    s.and_gate(temp4, temp_sum, carry_2_mult); // temp4 = temp_sum AND carry_2_mult
    s.and_gate(temp_and_mult, temp1, temp3); // temp_and_mult = temp1 AND temp3
    s.or_gate(carry_3_mult, temp4, temp_and_mult); // carry_3_mult = temp4 OR temp_and_mult

    s.and_gate(prod_4, ct1_2, ct2_2); // prod_4 = b1_2 * b2_2

    // decode each bits
    int prod_result_0 = s.decrypt(prod_0);
    int prod_result_1 = s.decrypt(prod_1);
    int prod_result_2 = s.decrypt(prod_2);
    int prod_result_3 = s.decrypt(prod_3);
    int prod_result_4 = s.decrypt(prod_4);

    // binary to decimal
    int prod_result = (prod_result_4 << 4) + (prod_result_3 << 3) + (prod_result_2 << 2) + (prod_result_1 << 1) + prod_result_0;

    cout << "[INFO] Result of 3 * 4: " << prod_result << endl;

    // //===================================================
    // test_params();
    // test_sampler();

    // cout << endl;
    // cout << "-------------------------" << endl;
    // cout << "NTRU tests" << endl;
    // SchemeNTRU s_ntru;
    // test_ntruhe_nand(s_ntru);
    // test_ntruhe_and(s_ntru);
    // test_ntruhe_or(s_ntru);
    // test_ntruhe_xor(s_ntru);
    // test_ntruhe_not(s_ntru);
    // test_ntruhe_composition_of_gates(s_ntru);
    // cout << "NTRU tests PASSED" << endl;

    // // cout << endl;
    // cout << "-------------------------" << endl;
    // cout << "LWE tests" << endl;
    // SchemeLWE s_lwe;
    // test_lwehe_not(s_lwe);
    // test_lwehe_nand(s_lwe);
    // test_lwehe_and(s_lwe);
    // test_lwehe_or(s_lwe);
    // test_lwehe_xor(s_lwe);
    // test_lwehe_not(s_lwe);
    // test_lwehe_composition_of_gates(s_lwe);
    // cout << "LWE tests PASSED" << endl;

    return 0;
}
