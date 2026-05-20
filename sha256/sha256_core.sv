`timescale 1ns / 1ps
// =============================================================================
// sha256_core.sv
//
// SHA-256 engine hardened for Ibex RISC-V secure boot.
//
// Changes from original:
//  1. H[] re-initialised to IVs on every new message, not just rst_n.
//  2. valid_out held until consumer drives hash_ack (no missed-pulse risk).
//  3. hash_out is registered — bus never carries a partial digest.
//  4. FSM one-hot encoded; illegal-state default forces back to IDLE.
//  5. Working variables zeroised after DONE (no state leakage).
//  6. ready_out gated so a new block cannot arrive while digest is pending.
//  7. Removed unused next_state declaration.
//  8. h renamed h_var to avoid $unit namespace collisions on some tools.
//  9. IVs promoted to localparams — single source of truth, no copy-paste risk.
// =============================================================================

module sha256_core (
    input  logic         clk,
    input  logic         rst_n,

    // Control
    input  logic         valid_in,   // pulse: new 512-bit block is ready
    input  logic         hash_ack,   // consumer acknowledges the digest
    output logic         ready_out,  // core is idle and can accept a block
    output logic         valid_out,  // digest on hash_out is valid and stable

    // Data
    input  logic [511:0] block_in,   // 512-bit message block (caller pre-pads)
    output logic [255:0] hash_out    // 256-bit digest (held until hash_ack)
);

    // =========================================================================
    // SHA-256 IV constants (FIPS 180-4 §5.3.3)
    // =========================================================================
    localparam logic [31:0] IV0 = 32'h6a09e667;
    localparam logic [31:0] IV1 = 32'hbb67ae85;
    localparam logic [31:0] IV2 = 32'h3c6ef372;
    localparam logic [31:0] IV3 = 32'ha54ff53a;
    localparam logic [31:0] IV4 = 32'h510e527f;
    localparam logic [31:0] IV5 = 32'h9b05688c;
    localparam logic [31:0] IV6 = 32'h1f83d9ab;
    localparam logic [31:0] IV7 = 32'h5be0cd19;

    // =========================================================================
    // Internal state
    // =========================================================================
    logic [31:0]  H      [0:7];  // persistent hash state
    logic [31:0]  a, b, c, d, e, f, g, h_var;  // working variables
    logic [31:0]  W      [0:15]; // 16-word sliding message schedule window
    logic [6:0]   round_ctr;
    logic [255:0] hash_out_r;    // registered output digest

    // =========================================================================
    // FSM — one-hot encoding for glitch resilience
    // =========================================================================
    typedef enum logic [2:0] {
        IDLE     = 3'b001,
        COMPRESS = 3'b010,
        DONE     = 3'b100
    } state_t;
    state_t state;

    // =========================================================================
    // Combinational: SHA-256 functions (FIPS 180-4 §4.1.2)
    // =========================================================================

    // Ch(e,f,g) — eq. 4.2
    logic [31:0] ch_out;
    assign ch_out = (e & f) ^ (~e & g);

    // Maj(a,b,c) — eq. 4.3
    logic [31:0] maj_out;
    assign maj_out = (a & b) ^ (a & c) ^ (b & c);

    // Σ₀(a) = ROTR2 ⊕ ROTR13 ⊕ ROTR22 — eq. 4.4
    logic [31:0] sum0_out;
    assign sum0_out = {a[1:0],  a[31:2]}  ^
                      {a[12:0], a[31:13]} ^
                      {a[21:0], a[31:22]};

    // Σ₁(e) = ROTR6 ⊕ ROTR11 ⊕ ROTR25 — eq. 4.5
    logic [31:0] sum1_out;
    assign sum1_out = {e[5:0],  e[31:6]}  ^
                      {e[10:0], e[31:11]} ^
                      {e[24:0], e[31:25]};

    // σ₀(W[t-15]) = ROTR7 ⊕ ROTR18 ⊕ SHR3 — eq. 4.6
    logic [31:0] sig0_out;
    assign sig0_out = {W[1][6:0],  W[1][31:7]}  ^
                      {W[1][17:0], W[1][31:18]} ^
                      (W[1] >> 3);

    // σ₁(W[t-2]) = ROTR17 ⊕ ROTR19 ⊕ SHR10 — eq. 4.7
    logic [31:0] sig1_out;
    assign sig1_out = {W[14][16:0], W[14][31:17]} ^
                      {W[14][18:0], W[14][31:19]} ^
                      (W[14] >> 10);

    // Next schedule word: σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16]
    logic [31:0] w_new;
    assign w_new = sig1_out + W[9] + sig0_out + W[0];

    // =========================================================================
    // K constants ROM (FIPS 180-4 §4.2.2)
    // =========================================================================
    logic [31:0] K_val;
    always_comb begin
        case (round_ctr)
            7'd0:  K_val = 32'h428a2f98; 7'd1:  K_val = 32'h71374491;
            7'd2:  K_val = 32'hb5c0fbcf; 7'd3:  K_val = 32'he9b5dba5;
            7'd4:  K_val = 32'h3956c25b; 7'd5:  K_val = 32'h59f111f1;
            7'd6:  K_val = 32'h923f82a4; 7'd7:  K_val = 32'hab1c5ed5;
            7'd8:  K_val = 32'hd807aa98; 7'd9:  K_val = 32'h12835b01;
            7'd10: K_val = 32'h243185be; 7'd11: K_val = 32'h550c7dc3;
            7'd12: K_val = 32'h72be5d74; 7'd13: K_val = 32'h80deb1fe;
            7'd14: K_val = 32'h9bdc06a7; 7'd15: K_val = 32'hc19bf174;
            7'd16: K_val = 32'he49b69c1; 7'd17: K_val = 32'hefbe4786;
            7'd18: K_val = 32'h0fc19dc6; 7'd19: K_val = 32'h240ca1cc;
            7'd20: K_val = 32'h2de92c6f; 7'd21: K_val = 32'h4a7484aa;
            7'd22: K_val = 32'h5cb0a9dc; 7'd23: K_val = 32'h76f988da;
            7'd24: K_val = 32'h983e5152; 7'd25: K_val = 32'ha831c66d;
            7'd26: K_val = 32'hb00327c8; 7'd27: K_val = 32'hbf597fc7;
            7'd28: K_val = 32'hc6e00bf3; 7'd29: K_val = 32'hd5a79147;
            7'd30: K_val = 32'h06ca6351; 7'd31: K_val = 32'h14292967;
            7'd32: K_val = 32'h27b70a85; 7'd33: K_val = 32'h2e1b2138;
            7'd34: K_val = 32'h4d2c6dfc; 7'd35: K_val = 32'h53380d13;
            7'd36: K_val = 32'h650a7354; 7'd37: K_val = 32'h766a0abb;
            7'd38: K_val = 32'h81c2c92e; 7'd39: K_val = 32'h92722c85;
            7'd40: K_val = 32'ha2bfe8a1; 7'd41: K_val = 32'ha81a664b;
            7'd42: K_val = 32'hc24b8b70; 7'd43: K_val = 32'hc76c51a3;
            7'd44: K_val = 32'hd192e819; 7'd45: K_val = 32'hd6990624;
            7'd46: K_val = 32'hf40e3585; 7'd47: K_val = 32'h106aa070;
            7'd48: K_val = 32'h19a4c116; 7'd49: K_val = 32'h1e376c08;
            7'd50: K_val = 32'h2748774c; 7'd51: K_val = 32'h34b0bcb5;
            7'd52: K_val = 32'h391c0cb3; 7'd53: K_val = 32'h4ed8aa4a;
            7'd54: K_val = 32'h5b9cca4f; 7'd55: K_val = 32'h682e6ff3;
            7'd56: K_val = 32'h748f82ee; 7'd57: K_val = 32'h78a5636f;
            7'd58: K_val = 32'h84c87814; 7'd59: K_val = 32'h8cc70208;
            7'd60: K_val = 32'h90befffa; 7'd61: K_val = 32'ha4506ceb;
            7'd62: K_val = 32'hbef9a3f7; 7'd63: K_val = 32'hc67178f2;
            default: K_val = 32'h00000000;
        endcase
    end

    // =========================================================================
    // T1, T2 — combinational; sample pre-update working vars correctly via
    // non-blocking assignment semantics in the always_ff below
    // =========================================================================
    logic [31:0] T1, T2;
    assign T1 = h_var + sum1_out + ch_out + K_val + W[0];
    assign T2 = sum0_out + maj_out;

    // =========================================================================
    // FSM + datapath
    // =========================================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= IDLE;
            round_ctr  <= 7'd0;
            valid_out  <= 1'b0;
            ready_out  <= 1'b1;
            hash_out_r <= 256'd0;

            {a, b, c, d, e, f, g, h_var} <= '0;

            H[0] <= IV0; H[1] <= IV1; H[2] <= IV2; H[3] <= IV3;
            H[4] <= IV4; H[5] <= IV5; H[6] <= IV6; H[7] <= IV7;

        end else begin

            // Acknowledge clears valid_out (evaluated every cycle)
            if (valid_out && hash_ack)
                valid_out <= 1'b0;

            case (state)

                // -------------------------------------------------------------
                IDLE: begin
                    if (valid_in && ready_out && !valid_out) begin
                        ready_out <= 1'b0;
                        state     <= COMPRESS;
                        round_ctr <= 7'd0;

                        // Re-load IVs for every new independent message
                        // (original bug: only happened on rst_n)
                        H[0] <= IV0; H[1] <= IV1; H[2] <= IV2; H[3] <= IV3;
                        H[4] <= IV4; H[5] <= IV5; H[6] <= IV6; H[7] <= IV7;

                        a     <= IV0; b <= IV1; c <= IV2; d     <= IV3;
                        e     <= IV4; f <= IV5; g <= IV6; h_var <= IV7;

                        // Load block big-endian (FIPS 180-4 §5.2.1)
                        for (int i = 0; i < 16; i++)
                            W[i] <= block_in[511 - i*32 -: 32];
                    end
                end

                // -------------------------------------------------------------
                COMPRESS: begin
                    // Round update (FIPS 180-4 §6.2.2 step 3)
                    h_var <= g;
                    g     <= f;
                    f     <= e;
                    e     <= d + T1;
                    d     <= c;
                    c     <= b;
                    b     <= a;
                    a     <= T1 + T2;

                    // Slide schedule window
                    for (int i = 0; i < 15; i++)
                        W[i] <= W[i+1];
                    W[15] <= w_new;

                    if (round_ctr == 7'd63)
                        state <= DONE;
                    else
                        round_ctr <= round_ctr + 1'b1;
                end

                // -------------------------------------------------------------
                DONE: begin
                    // Accumulate (FIPS 180-4 §6.2.2 step 4)
                    H[0] <= H[0] + a;     H[1] <= H[1] + b;
                    H[2] <= H[2] + c;     H[3] <= H[3] + d;
                    H[4] <= H[4] + e;     H[5] <= H[5] + f;
                    H[6] <= H[6] + g;     H[7] <= H[7] + h_var;

                    // Register output atomically — bus never shows partial state
                    // (original: continuous assign from H[] exposed intermediate)
                    hash_out_r <= {H[0] + a, H[1] + b, H[2] + c, H[3] + d,
                                   H[4] + e, H[5] + f, H[6] + g, H[7] + h_var};

                    valid_out <= 1'b1;
                    ready_out <= 1'b1;
                    state     <= IDLE;

                    // Zeroise working variables — no digest leakage
                    {a, b, c, d, e, f, g, h_var} <= '0;
                end

                // -------------------------------------------------------------
                // Illegal state — fault/glitch recovery
                default: begin
                    state     <= IDLE;
                    ready_out <= 1'b1;
                    valid_out <= 1'b0;
                end

            endcase
        end
    end

    // =========================================================================
    // Output — registered, held stable until hash_ack
    // =========================================================================
    assign hash_out = hash_out_r;

endmodule
