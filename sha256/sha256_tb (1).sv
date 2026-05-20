// =============================================================================
// sha256_tb.sv
//
// Testbench for sha256_core.sv (hardened version).
//
// HOW TO RUN:
//   iverilog -g2012 -o sim sha256_tb.sv sha256_core.sv && vvp sim
//
// WHAT TO CHECK:
//   Every test should print PASS with matching Expected / Got lines.
//   On FAIL the word-by-word breakdown shows exactly which H word is wrong.
//
// Test vectors (NIST FIPS 180-4 examples):
//   Vec 1 : "abc"
//   Vec 2 : "" (empty string)
//   Vec 3 : "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
//            (two-block message — exercises multi-block path)
// =============================================================================

`timescale 1ns/1ps

module sha256_tb;

    // -------------------------------------------------------------------------
    // DUT signals — match sha256_core.sv port list exactly
    // -------------------------------------------------------------------------
    logic         clk;
    logic         rst_n;
    logic         valid_in;
    logic         hash_ack;
    logic         ready_out;
    logic         valid_out;
    logic [511:0] block_in;
    logic [255:0] hash_out;

    // -------------------------------------------------------------------------
    // DUT instantiation
    // -------------------------------------------------------------------------
    sha256_core dut (
        .clk       (clk),
        .rst_n     (rst_n),
        .valid_in  (valid_in),
        .hash_ack  (hash_ack),
        .ready_out (ready_out),
        .valid_out (valid_out),
        .block_in  (block_in),
        .hash_out  (hash_out)
    );

    // 10 ns clock
    always #5 clk = ~clk;

    // =========================================================================
    // NIST Test Vector 1 — "abc"
    // Input bytes : 0x61 0x62 0x63 (24 bits)
    // Padded block: 61626380 00...00 00000018
    // Expected    : ba7816bf 8f01cfea 414140de 5dae2ec7
    //               3b359713 21f9c1ee 18ca3b29 b0d8c9a9
    // =========================================================================
    localparam [511:0] VEC1_BLOCK = {
        32'h61626380,                               // "abc" + pad bit
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000,
        32'h00000018                                // length = 24 bits
    };
    localparam [255:0] VEC1_EXPECTED =
        256'hba7816bf_8f01cfea_414140de_5dae2ec7_3b359713_21f9c1ee_18ca3b29_b0d8c9a9;

    // =========================================================================
    // NIST Test Vector 2 — "" (empty string)
    // Padded block: 80000000 00...00 00000000
    // Expected    : e3b0c442 98fc1c14 9afbf4c8 996fb924
    //               27ae41e4 649b934c a495991b 7852b855
    // =========================================================================
    localparam [511:0] VEC2_BLOCK = {
        32'h80000000,                               // pad bit only
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000,
        32'h00000000                                // length = 0 bits
    };
    localparam [255:0] VEC2_EXPECTED =
        256'he3b0c442_98fc1c14_9afbf4c8_996fb924_27ae41e4_649b934c_a495991b_7852b855;

    // =========================================================================
    // NIST Test Vector 3 — 448-bit message (two blocks)
    // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    //
    // Block 1 (bytes 0-63):
    //   61626364 62636465 63646566 64656667
    //   65666768 66676869 6768696a 68696a6b
    //   696a6b6c 6a6b6c6d 6b6c6d6e 6c6d6e6f
    //   6d6e6f70 6e6f7071 80000000 00000000
    //
    // Block 2 (padding + length):
    //   00000000 ... 00000000 000001c0
    //   (length = 448 bits = 0x1c0)
    //
    // Expected : 248d6a61 d20638b8 e5c02693 0c3e6039
    //            a33ce459 64ff2167 f6ecedd4 19db06c1
    // =========================================================================
    localparam [511:0] VEC3_BLOCK1 = {
        32'h61626364, 32'h62636465, 32'h63646566, 32'h64656667,
        32'h65666768, 32'h66676869, 32'h6768696a, 32'h68696a6b,
        32'h696a6b6c, 32'h6a6b6c6d, 32'h6b6c6d6e, 32'h6c6d6e6f,
        32'h6d6e6f70, 32'h6e6f7071, 32'h80000000, 32'h00000000
    };
    localparam [511:0] VEC3_BLOCK2 = {
        32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
        32'h00000000, 32'h00000000, 32'h00000000, 32'h000001c0
    };
    localparam [255:0] VEC3_EXPECTED =
        256'h248d6a61_d20638b8_e5c02693_0c3e6039_a33ce459_64ff2167_f6ecedd4_19db06c1;

    // =========================================================================
    // Pass / fail counters
    // =========================================================================
    int pass_count = 0;
    int fail_count = 0;

    // =========================================================================
    // Task: pretty-print expected vs calculated, word by word
    // =========================================================================
    task automatic print_comparison(
        input [255:0] expected,
        input [255:0] got
    );
        logic [31:0] e_word, g_word;
        string       marker;
        $display("  %-6s  %-10s  %-10s", "Word", "Expected", "Got");
        $display("  %-6s  %-10s  %-10s", "------", "----------", "----------");
        for (int i = 0; i < 8; i++) begin
            e_word = expected[255 - i*32 -: 32];
            g_word = got     [255 - i*32 -: 32];
            marker = (e_word === g_word) ? "  " : "<< MISMATCH";
            $display("  H[%0d]   %08h    %08h  %s",
                     i, e_word, g_word, marker);
        end
    endtask

    // =========================================================================
    // Task: run a single-block hash and check
    // =========================================================================
    task automatic run_single(
        input [511:0] block,
        input [255:0] expected,
        input string  name
    );
        // Wait for core ready
        @(posedge clk);
        while (!ready_out) @(posedge clk);

        // Present block
        block_in  <= block;
        valid_in  <= 1'b1;
        @(posedge clk);
        valid_in  <= 1'b0;

        // Wait for valid_out
        while (!valid_out) @(posedge clk);

        // Print result
        $display("\n--- Test: %s ---", name);
        $display("  Input block (hex): %0h", block);
        print_comparison(expected, hash_out);

        if (hash_out === expected) begin
            $display("  Result: PASS");
            pass_count++;
        end else begin
            $display("  Result: FAIL");
            fail_count++;
        end

        // Acknowledge digest so core can accept next block
        hash_ack <= 1'b1;
        @(posedge clk);
        hash_ack <= 1'b0;

        repeat(4) @(posedge clk);
    endtask

    // =========================================================================
    // Task: run a two-block hash (no IV reset between blocks — same message)
    // NOTE: for multi-block the hardened core re-loads IVs on valid_in, so
    //       for a continuation block we need a version that does NOT reset H[].
    //       In the current sha256_core design each valid_in starts a fresh
    //       message — so two-block hashing requires a wrapper or the core to
    //       be extended with a 'first_block' flag.
    //       This test is included as a KNOWN-LIMITATION marker and will FAIL
    //       until the core supports chained blocks.  It still prints the
    //       word-by-word breakdown so you can see how far off it is.
    // =========================================================================
    task automatic run_two_block(
        input [511:0] block1,
        input [511:0] block2,
        input [255:0] expected,
        input string  name
    );
        // Block 1
        @(posedge clk);
        while (!ready_out) @(posedge clk);
        block_in <= block1;
        valid_in <= 1'b1;
        @(posedge clk);
        valid_in <= 1'b0;
        while (!valid_out) @(posedge clk);
        // Do NOT ack yet — in a real chained design we would feed block2
        // without resetting H[].  With current core, ack then re-submit.
        hash_ack <= 1'b1;
        @(posedge clk);
        hash_ack <= 1'b0;
        repeat(2) @(posedge clk);

        // Block 2
        while (!ready_out) @(posedge clk);
        block_in <= block2;
        valid_in <= 1'b1;
        @(posedge clk);
        valid_in <= 1'b0;
        while (!valid_out) @(posedge clk);

        $display("\n--- Test: %s (two-block) ---", name);
        $display("  NOTE: core resets H[] per message — multi-block");
        $display("        chaining not yet supported. Result will FAIL.");
        print_comparison(expected, hash_out);

        if (hash_out === expected) begin
            $display("  Result: PASS");
            pass_count++;
        end else begin
            $display("  Result: FAIL (expected — see note above)");
            fail_count++;
        end

        hash_ack <= 1'b1;
        @(posedge clk);
        hash_ack <= 1'b0;
        repeat(4) @(posedge clk);
    endtask

    // =========================================================================
    // Main sequence
    // =========================================================================
    initial begin
        clk      = 0;
        rst_n    = 0;
        valid_in = 0;
        hash_ack = 0;
        block_in = '0;

        repeat(4) @(posedge clk);
        rst_n = 1;
        repeat(2) @(posedge clk);

        $display("\n========================================");
        $display("  SHA-256 NIST Vector Tests");
        $display("  DUT: sha256_core (hardened)");
        $display("========================================");

        run_single(VEC1_BLOCK, VEC1_EXPECTED, "abc");
        run_single(VEC2_BLOCK, VEC2_EXPECTED, "empty string");
        run_two_block(VEC3_BLOCK1, VEC3_BLOCK2, VEC3_EXPECTED,
                      "abcdbcdecdef...nopq (448-bit, 2 blocks)");

        $display("\n========================================");
        $display("  Summary: %0d PASS  /  %0d FAIL", pass_count, fail_count);
        $display("========================================\n");

        $finish;
    end

    // =========================================================================
    // Timeout watchdog — 200k cycles
    // =========================================================================
    initial begin
        #2000000;
        $display("TIMEOUT — simulation exceeded 200k cycles");
        $finish;
    end

endmodule
