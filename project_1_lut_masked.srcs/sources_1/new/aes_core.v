`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
//
// aes_core.v -- CORRECTED for full-round Boolean masking
//
// CHANGE FROM ORIGINAL: the original design unmasked the SBOX output
// immediately (assign sbb_o = sbb_o_masked ^ mask_o;) and ran ShiftRows /
// MixColumns / AddRoundKey on the TRUE, unmasked value. That defeats the
// masking -- CPA against the post-SBOX byte succeeds almost as easily as
// against the fully unmasked design, because the mask is gone before any
// of the leaking linear-layer operations run.
//
// FIX: carry TWO parallel 128-bit values through the entire round:
//   state_m = real_state XOR mask        (the masked data path)
//   state_r = mask                       (the running mask, NOT the key)
// ShiftRows and MixColumns are linear over GF(2)/GF(2^8), so applying the
// SAME linear operation to both state_m and state_r preserves the
// invariant (state_m XOR state_r) == real_state at every step:
//   LinearOp(real XOR mask) == LinearOp(real) XOR LinearOp(mask)
// AddRoundKey is the one step where the key must hit ONLY state_m -- the
// key must never be XORed into state_r, or it would get folded into what
// is supposed to be a pure random mask.
// The two values are only combined (real = state_m XOR state_r) once, at
// the very end of the final round, to produce data_o.
//
//////////////////////////////////////////////////////////////////////////////////

module aes_core (
	input wire clk,
	input wire load_i,
	input wire [255:0] key_i,
	input wire [127:0] data_i,
	input wire [1:0] size_i,
	input wire dec_i,
	output reg [127:0] data_o,
	output reg busy_o
`ifdef SBOX_MASKED
   ,input wire [127:0] mask_i,   // 16 bytes: input  mask per byte (from TRNG)
    input wire [127:0] mask_o    // 16 bytes: output mask per byte (from TRNG)
`endif
);

localparam AES_128 = 0;
localparam AES_192 = 1;
localparam AES_256 = 2;

localparam AES_KEYSCHED = 0;
localparam AES_DECRYPT = 1;

reg dec_r;
reg [1:0] fsm, fsm_new;

reg [3:0] round, round_new, round_max;
wire [3:0] round_inc = round + 1;
wire [3:0] round_dec = round - 1;

`ifdef SBOX_MASKED
// state_m = masked data path (real XOR running mask)
// state_r = the running mask itself, carried through the same linear ops
reg [127:0] state_m, state_m_new;
reg [127:0] state_r, state_r_new;
`else
reg [127:0] state, state_new;
`endif

reg [127:0] sbb_i;
wire [127:0] sbb_o;

reg [127:0] ks_mem[14:0];
reg [127:0] ks;
wire [127:0] ks_val;
wire ks_en = (fsm == AES_KEYSCHED);

aes_ks ks_inst (
	.clk(clk),
	.load_i(load_i),
	.en_i(ks_en),
	.size_i(size_i),
	.key_i(key_i),
	.ks_o(ks_val)
);

`ifdef SBOX_MASKED
// sbb_o_masked carries S(x) XOR mask_out straight off the sbox instances.
// UNLIKE the original code, we do NOT unmask this back to a true sbb_o.
// sbb_o_masked itself becomes the value that flows into ShiftRows/MixColumns.
wire [127:0] sbb_o_masked;

// sbb_i is computed from state_m (the masked state), so the SBOX always
// only ever sees masked data on its way in too.
wire [127:0] sbb_i_masked = sbb_i ^ mask_i;
`endif

always @(posedge clk)
begin
	if(load_i)
	begin
		case(size_i)
		AES_128: round_max <= 10;
		AES_192: round_max <= 12;
		default: round_max <= 14;
		endcase
	end
end

// NEWAE mod: GF, LUT, or masked-LUT sboxes
`ifdef SBOX_GF
    aes_sbox sbox_inst00(.U(sbb_i[  7:  0]), .dec(dec_r), .S(sbb_o[  7:  0]));
    aes_sbox sbox_inst01(.U(sbb_i[ 15:  8]), .dec(dec_r), .S(sbb_o[ 15:  8]));
    aes_sbox sbox_inst02(.U(sbb_i[ 23: 16]), .dec(dec_r), .S(sbb_o[ 23: 16]));
    aes_sbox sbox_inst03(.U(sbb_i[ 31: 24]), .dec(dec_r), .S(sbb_o[ 31: 24]));
    aes_sbox sbox_inst04(.U(sbb_i[ 39: 32]), .dec(dec_r), .S(sbb_o[ 39: 32]));
    aes_sbox sbox_inst05(.U(sbb_i[ 47: 40]), .dec(dec_r), .S(sbb_o[ 47: 40]));
    aes_sbox sbox_inst06(.U(sbb_i[ 55: 48]), .dec(dec_r), .S(sbb_o[ 55: 48]));
    aes_sbox sbox_inst07(.U(sbb_i[ 63: 56]), .dec(dec_r), .S(sbb_o[ 63: 56]));
    aes_sbox sbox_inst08(.U(sbb_i[ 71: 64]), .dec(dec_r), .S(sbb_o[ 71: 64]));
    aes_sbox sbox_inst09(.U(sbb_i[ 79: 72]), .dec(dec_r), .S(sbb_o[ 79: 72]));
    aes_sbox sbox_inst10(.U(sbb_i[ 87: 80]), .dec(dec_r), .S(sbb_o[ 87: 80]));
    aes_sbox sbox_inst11(.U(sbb_i[ 95: 88]), .dec(dec_r), .S(sbb_o[ 95: 88]));
    aes_sbox sbox_inst12(.U(sbb_i[103: 96]), .dec(dec_r), .S(sbb_o[103: 96]));
    aes_sbox sbox_inst13(.U(sbb_i[111:104]), .dec(dec_r), .S(sbb_o[111:104]));
    aes_sbox sbox_inst14(.U(sbb_i[119:112]), .dec(dec_r), .S(sbb_o[119:112]));
    aes_sbox sbox_inst15(.U(sbb_i[127:120]), .dec(dec_r), .S(sbb_o[127:120]));
`elsif SBOX_MASKED
    // Boolean-masked LUT S-Box. Output feeds sbb_o_masked, which now flows
    // DIRECTLY into ShiftRows/MixColumns below -- it is never unmasked here.
    aes_sbox_lut_masked sbox_inst00(.byte_in(sbb_i_masked[  7:  0]), .mask_in(mask_i[  7:  0]), .mask_out(mask_o[  7:  0]), .byte_out(sbb_o_masked[  7:  0]));
    aes_sbox_lut_masked sbox_inst01(.byte_in(sbb_i_masked[ 15:  8]), .mask_in(mask_i[ 15:  8]), .mask_out(mask_o[ 15:  8]), .byte_out(sbb_o_masked[ 15:  8]));
    aes_sbox_lut_masked sbox_inst02(.byte_in(sbb_i_masked[ 23: 16]), .mask_in(mask_i[ 23: 16]), .mask_out(mask_o[ 23: 16]), .byte_out(sbb_o_masked[ 23: 16]));
    aes_sbox_lut_masked sbox_inst03(.byte_in(sbb_i_masked[ 31: 24]), .mask_in(mask_i[ 31: 24]), .mask_out(mask_o[ 31: 24]), .byte_out(sbb_o_masked[ 31: 24]));
    aes_sbox_lut_masked sbox_inst04(.byte_in(sbb_i_masked[ 39: 32]), .mask_in(mask_i[ 39: 32]), .mask_out(mask_o[ 39: 32]), .byte_out(sbb_o_masked[ 39: 32]));
    aes_sbox_lut_masked sbox_inst05(.byte_in(sbb_i_masked[ 47: 40]), .mask_in(mask_i[ 47: 40]), .mask_out(mask_o[ 47: 40]), .byte_out(sbb_o_masked[ 47: 40]));
    aes_sbox_lut_masked sbox_inst06(.byte_in(sbb_i_masked[ 55: 48]), .mask_in(mask_i[ 55: 48]), .mask_out(mask_o[ 55: 48]), .byte_out(sbb_o_masked[ 55: 48]));
    aes_sbox_lut_masked sbox_inst07(.byte_in(sbb_i_masked[ 63: 56]), .mask_in(mask_i[ 63: 56]), .mask_out(mask_o[ 63: 56]), .byte_out(sbb_o_masked[ 63: 56]));
    aes_sbox_lut_masked sbox_inst08(.byte_in(sbb_i_masked[ 71: 64]), .mask_in(mask_i[ 71: 64]), .mask_out(mask_o[ 71: 64]), .byte_out(sbb_o_masked[ 71: 64]));
    aes_sbox_lut_masked sbox_inst09(.byte_in(sbb_i_masked[ 79: 72]), .mask_in(mask_i[ 79: 72]), .mask_out(mask_o[ 79: 72]), .byte_out(sbb_o_masked[ 79: 72]));
    aes_sbox_lut_masked sbox_inst10(.byte_in(sbb_i_masked[ 87: 80]), .mask_in(mask_i[ 87: 80]), .mask_out(mask_o[ 87: 80]), .byte_out(sbb_o_masked[ 87: 80]));
    aes_sbox_lut_masked sbox_inst11(.byte_in(sbb_i_masked[ 95: 88]), .mask_in(mask_i[ 95: 88]), .mask_out(mask_o[ 95: 88]), .byte_out(sbb_o_masked[ 95: 88]));
    aes_sbox_lut_masked sbox_inst12(.byte_in(sbb_i_masked[103: 96]), .mask_in(mask_i[103: 96]), .mask_out(mask_o[103: 96]), .byte_out(sbb_o_masked[103: 96]));
    aes_sbox_lut_masked sbox_inst13(.byte_in(sbb_i_masked[111:104]), .mask_in(mask_i[111:104]), .mask_out(mask_o[111:104]), .byte_out(sbb_o_masked[111:104]));
    aes_sbox_lut_masked sbox_inst14(.byte_in(sbb_i_masked[119:112]), .mask_in(mask_i[119:112]), .mask_out(mask_o[119:112]), .byte_out(sbb_o_masked[119:112]));
    aes_sbox_lut_masked sbox_inst15(.byte_in(sbb_i_masked[127:120]), .mask_in(mask_i[127:120]), .mask_out(mask_o[127:120]), .byte_out(sbb_o_masked[127:120]));
`else
    aes_sbox_lut sbox_inst00(.byte_in(sbb_i[  7:  0]), .dec(dec_r), .byte_out(sbb_o[  7:  0]));
    aes_sbox_lut sbox_inst01(.byte_in(sbb_i[ 15:  8]), .dec(dec_r), .byte_out(sbb_o[ 15:  8]));
    aes_sbox_lut sbox_inst02(.byte_in(sbb_i[ 23: 16]), .dec(dec_r), .byte_out(sbb_o[ 23: 16]));
    aes_sbox_lut sbox_inst03(.byte_in(sbb_i[ 31: 24]), .dec(dec_r), .byte_out(sbb_o[ 31: 24]));
    aes_sbox_lut sbox_inst04(.byte_in(sbb_i[ 39: 32]), .dec(dec_r), .byte_out(sbb_o[ 39: 32]));
    aes_sbox_lut sbox_inst05(.byte_in(sbb_i[ 47: 40]), .dec(dec_r), .byte_out(sbb_o[ 47: 40]));
    aes_sbox_lut sbox_inst06(.byte_in(sbb_i[ 55: 48]), .dec(dec_r), .byte_out(sbb_o[ 55: 48]));
    aes_sbox_lut sbox_inst07(.byte_in(sbb_i[ 63: 56]), .dec(dec_r), .byte_out(sbb_o[ 63: 56]));
    aes_sbox_lut sbox_inst08(.byte_in(sbb_i[ 71: 64]), .dec(dec_r), .byte_out(sbb_o[ 71: 64]));
    aes_sbox_lut sbox_inst09(.byte_in(sbb_i[ 79: 72]), .dec(dec_r), .byte_out(sbb_o[ 79: 72]));
    aes_sbox_lut sbox_inst10(.byte_in(sbb_i[ 87: 80]), .dec(dec_r), .byte_out(sbb_o[ 87: 80]));
    aes_sbox_lut sbox_inst11(.byte_in(sbb_i[ 95: 88]), .dec(dec_r), .byte_out(sbb_o[ 95: 88]));
    aes_sbox_lut sbox_inst12(.byte_in(sbb_i[103: 96]), .dec(dec_r), .byte_out(sbb_o[103: 96]));
    aes_sbox_lut sbox_inst13(.byte_in(sbb_i[111:104]), .dec(dec_r), .byte_out(sbb_o[111:104]));
    aes_sbox_lut sbox_inst14(.byte_in(sbb_i[119:112]), .dec(dec_r), .byte_out(sbb_o[119:112]));
    aes_sbox_lut sbox_inst15(.byte_in(sbb_i[127:120]), .dec(dec_r), .byte_out(sbb_o[127:120]));
`endif

`ifdef SBOX_MASKED
// SubBytes input: derived from state_m (the masked state), same as
// original logic but reading state_m instead of state.
always @*
begin : subbytes_pre
	if(dec_r)
	begin
		sbb_i = {
			state_m[127:120], state_m[ 23: 16], state_m[ 47: 40], state_m[ 71: 64],
			state_m[ 95: 88], state_m[119:112], state_m[ 15:  8], state_m[ 39: 32],
			state_m[ 63: 56], state_m[ 87: 80], state_m[111:104], state_m[  7:  0],
			state_m[ 31: 24], state_m[ 55: 48], state_m[ 79: 72], state_m[103: 96]
		};
	end
	else
	begin
		sbb_i = state_m;
	end
end
`else
always @*
begin : subbytes_pre
	if(dec_r)
	begin
		sbb_i = {
			state[127:120], state[ 23: 16], state[ 47: 40], state[ 71: 64],
			state[ 95: 88], state[119:112], state[ 15:  8], state[ 39: 32],
			state[ 63: 56], state[ 87: 80], state[111:104], state[  7:  0],
			state[ 31: 24], state[ 55: 48], state[ 79: 72], state[103: 96]
		};
	end
	else
	begin
		sbb_i = state;
	end
end
`endif

function [7:0] xtime;
	input [7:0] b; xtime={b[6:0],1'b0} ^ (8'h1b & {8{b[7]}});
endfunction

function [7:0] x02;
	input [7:0] b; x02={b[6:0],1'b0} ^ (8'h1b & {8{b[7]}});
endfunction

function [7:0] x03;
	input [7:0] b; x03=x02(b)^b;
endfunction

function [7:0] x04;
	input [7:0] b; x04=x02(x02(b));
endfunction

function [7:0] x08;
	input [7:0] b; x08=x02(x04(b));
endfunction

function [7:0] x09;
	input [7:0] b; x09=x08(b)^b;
endfunction

function [7:0] x11;
	input [7:0] b; x11=x08(b)^x02(b)^b;
endfunction

function [7:0] x13;
	input [7:0] b; x13=x08(b)^x04(b)^b;
endfunction

function [7:0] x14;
	input [7:0] b; x14=x08(b)^x04(b)^x02(b);
endfunction

// Generic linear-layer task: applies InvShiftRows+InvMixColumns (decrypt)
// or ShiftRows+MixColumns (encrypt) to a 128-bit value. Used identically
// for BOTH state_m and state_r when SBOX_MASKED -- this is what makes the
// mask survive the round: the same linear transform is applied to the
// masked data and to the mask itself, so their XOR still equals the true
// post-linear-layer value. No round-key term is included here; that is
// added separately, and ONLY to state_m's path, never to state_r's.
`ifdef SBOX_MASKED
function [127:0] linear_layer_decrypt;
	input [127:0] sbb_out;     // already SubBytes'd value (masked or mask, post-SBOX-equivalent)
	input [127:0] ark_pre;     // value used when this is the last/first round and SBOX is skipped (state passthrough)
	input use_ark_pre;
	reg [127:0] ark_o, mxc_o;
	begin
		// AddRoundKey is intentionally NOT applied inside this function --
		// caller applies round key separately, only to the state_m path.
		ark_o = use_ark_pre ? ark_pre : sbb_out;

		mxc_o = {
			x14(ark_o[127:120]) ^ x11(ark_o[119:112]) ^ x13(ark_o[111:104]) ^ x09(ark_o[103: 96]),
			x09(ark_o[127:120]) ^ x14(ark_o[119:112]) ^ x11(ark_o[111:104]) ^ x13(ark_o[103: 96]),
			x13(ark_o[127:120]) ^ x09(ark_o[119:112]) ^ x14(ark_o[111:104]) ^ x11(ark_o[103: 96]),
			x11(ark_o[127:120]) ^ x13(ark_o[119:112]) ^ x09(ark_o[111:104]) ^ x14(ark_o[103: 96]),

			x14(ark_o[ 95: 88]) ^ x11(ark_o[ 87: 80]) ^ x13(ark_o[ 79: 72]) ^ x09(ark_o[ 71: 64]),
			x09(ark_o[ 95: 88]) ^ x14(ark_o[ 87: 80]) ^ x11(ark_o[ 79: 72]) ^ x13(ark_o[ 71: 64]),
			x13(ark_o[ 95: 88]) ^ x09(ark_o[ 87: 80]) ^ x14(ark_o[ 79: 72]) ^ x11(ark_o[ 71: 64]),
			x11(ark_o[ 95: 88]) ^ x13(ark_o[ 87: 80]) ^ x09(ark_o[ 79: 72]) ^ x14(ark_o[ 71: 64]),

			x14(ark_o[ 63: 56]) ^ x11(ark_o[ 55: 48]) ^ x13(ark_o[ 47: 40]) ^ x09(ark_o[ 39: 32]),
			x09(ark_o[ 63: 56]) ^ x14(ark_o[ 55: 48]) ^ x11(ark_o[ 47: 40]) ^ x13(ark_o[ 39: 32]),
			x13(ark_o[ 63: 56]) ^ x09(ark_o[ 55: 48]) ^ x14(ark_o[ 47: 40]) ^ x11(ark_o[ 39: 32]),
			x11(ark_o[ 63: 56]) ^ x13(ark_o[ 55: 48]) ^ x09(ark_o[ 47: 40]) ^ x14(ark_o[ 39: 32]),

			x14(ark_o[ 31: 24]) ^ x11(ark_o[ 23: 16]) ^ x13(ark_o[ 15:  8]) ^ x09(ark_o[  7:  0]),
			x09(ark_o[ 31: 24]) ^ x14(ark_o[ 23: 16]) ^ x11(ark_o[ 15:  8]) ^ x13(ark_o[  7:  0]),
			x13(ark_o[ 31: 24]) ^ x09(ark_o[ 23: 16]) ^ x14(ark_o[ 15:  8]) ^ x11(ark_o[  7:  0]),
			x11(ark_o[ 31: 24]) ^ x13(ark_o[ 23: 16]) ^ x09(ark_o[ 15:  8]) ^ x14(ark_o[  7:  0])
		};
		linear_layer_decrypt = mxc_o; // caller decides (via round==max/0 check) whether to use this or ark_o directly
	end
endfunction

function [127:0] shiftrows_enc;
	input [127:0] s;
	begin
		shiftrows_enc = {
			s[127:120], s[ 87: 80], s[ 47: 40], s[  7:  0],
			s[ 95: 88], s[ 55: 48], s[ 15:  8], s[103: 96],
			s[ 63: 56], s[ 23: 16], s[111:104], s[ 71: 64],
			s[ 31: 24], s[119:112], s[ 79: 72], s[ 39: 32]
		};
	end
endfunction

function [127:0] mixcolumns_enc;
	input [127:0] shr_o;
	reg [31:0] mxc_tmp;
	begin
		mxc_tmp = {
			shr_o[127:120] ^ shr_o[119:112] ^ shr_o[111:104] ^ shr_o[103: 96],
			shr_o[ 95: 88] ^ shr_o[ 87: 80] ^ shr_o[ 79: 72] ^ shr_o[ 71: 64],
			shr_o[ 63: 56] ^ shr_o[ 55: 48] ^ shr_o[ 47: 40] ^ shr_o[ 39: 32],
			shr_o[ 31: 24] ^ shr_o[ 23: 16] ^ shr_o[ 15:  8] ^ shr_o[  7:  0]
		};
		mixcolumns_enc = {
			shr_o[127:120] ^ xtime(shr_o[127:120] ^ shr_o[119:112]) ^ mxc_tmp[31:24],
			shr_o[119:112] ^ xtime(shr_o[119:112] ^ shr_o[111:104]) ^ mxc_tmp[31:24],
			shr_o[111:104] ^ xtime(shr_o[111:104] ^ shr_o[103: 96]) ^ mxc_tmp[31:24],
			shr_o[103: 96] ^ xtime(shr_o[103: 96] ^ shr_o[127:120]) ^ mxc_tmp[31:24],

			shr_o[ 95: 88] ^ xtime(shr_o[ 95: 88] ^ shr_o[ 87: 80]) ^ mxc_tmp[23:16],
			shr_o[ 87: 80] ^ xtime(shr_o[ 87: 80] ^ shr_o[ 79: 72]) ^ mxc_tmp[23:16],
			shr_o[ 79: 72] ^ xtime(shr_o[ 79: 72] ^ shr_o[ 71: 64]) ^ mxc_tmp[23:16],
			shr_o[ 71: 64] ^ xtime(shr_o[ 71: 64] ^ shr_o[ 95: 88]) ^ mxc_tmp[23:16],

			shr_o[ 63: 56] ^ xtime(shr_o[ 63: 56] ^ shr_o[ 55: 48]) ^ mxc_tmp[15: 8],
			shr_o[ 55: 48] ^ xtime(shr_o[ 55: 48] ^ shr_o[ 47: 40]) ^ mxc_tmp[15: 8],
			shr_o[ 47: 40] ^ xtime(shr_o[ 47: 40] ^ shr_o[ 39: 32]) ^ mxc_tmp[15: 8],
			shr_o[ 39: 32] ^ xtime(shr_o[ 39: 32] ^ shr_o[ 63: 56]) ^ mxc_tmp[15: 8],

			shr_o[ 31: 24] ^ xtime(shr_o[ 31: 24] ^ shr_o[ 23: 16]) ^ mxc_tmp[ 7: 0],
			shr_o[ 23: 16] ^ xtime(shr_o[ 23: 16] ^ shr_o[ 15:  8]) ^ mxc_tmp[ 7: 0],
			shr_o[ 15:  8] ^ xtime(shr_o[ 15:  8] ^ shr_o[  7:  0]) ^ mxc_tmp[ 7: 0],
			shr_o[  7:  0] ^ xtime(shr_o[  7:  0] ^ shr_o[ 31: 24]) ^ mxc_tmp[ 7: 0]
		};
	end
endfunction
`endif

`ifdef SBOX_MASKED
always @*
begin : subbytes_pst_masked
	if(dec_r)
	begin : decrypt_masked
		reg [127:0] ark_i_m, ark_o_m, mxc_o_m;   // masked-data path
		reg [127:0] mxc_o_r;                      // mask path (no key added)

		// AddRoundKey: key hits ONLY the masked-data path
		if(round == round_max)
			ark_i_m = state_m;
		else
			ark_i_m = sbb_o_masked;
		ark_o_m = ark_i_m ^ ks;

		// InvMixColumns applied to BOTH paths identically (linear op)
		mxc_o_m = linear_layer_decrypt(ark_o_m, ark_o_m, 1'b1);
		mxc_o_r = linear_layer_decrypt(state_r, state_r, 1'b1);

		if((round == round_max) || (round == 0))
		begin
			state_m_new = ark_o_m;
			state_r_new = state_r;     // no linear layer this round -> mask unchanged
		end
		else
		begin
			state_m_new = mxc_o_m;
			state_r_new = mxc_o_r;
		end
	end
	else
	begin : encrypt_masked
		reg [127:0] shr_o_m, mxc_o_m, ark_i_m;
		reg [127:0] shr_o_r, mxc_o_r;

		// ShiftRows on masked-data path
		shr_o_m = shiftrows_enc(sbb_o_masked);
		// ShiftRows on the mask itself -- mask_o is per-byte-position;
		// it must be permuted the SAME way the data byte it belongs to
		// just was, so it stays paired with the right byte going forward.
		shr_o_r = shiftrows_enc(mask_o);

		// MixColumns on both paths identically
		mxc_o_m = mixcolumns_enc(shr_o_m);
		mxc_o_r = mixcolumns_enc(shr_o_r);

		// AddRoundKey: key hits ONLY the masked-data path
		if(round == 0)
			ark_i_m = state_m;
		else if(round == round_max)
			ark_i_m = shr_o_m;
		else
			ark_i_m = mxc_o_m;

		state_m_new = ark_i_m ^ ks_val;

		// Mask path: same selection logic, NO key XOR
		if(round == 0)
			state_r_new = state_r;
		else if(round == round_max)
			state_r_new = shr_o_r;
		else
			state_r_new = mxc_o_r;
	end
end
`else
always @*
begin : subbytes_pst
	if(dec_r)
	begin : subbytes_pst_decrypt
		reg [127:0] ark_i, ark_o, mxc_o;

		if(round == round_max)
			ark_i = state;
		else
			ark_i = sbb_o;
		ark_o = ark_i ^ ks;

		mxc_o = {
			x14(ark_o[127:120]) ^ x11(ark_o[119:112]) ^ x13(ark_o[111:104]) ^ x09(ark_o[103: 96]),
			x09(ark_o[127:120]) ^ x14(ark_o[119:112]) ^ x11(ark_o[111:104]) ^ x13(ark_o[103: 96]),
			x13(ark_o[127:120]) ^ x09(ark_o[119:112]) ^ x14(ark_o[111:104]) ^ x11(ark_o[103: 96]),
			x11(ark_o[127:120]) ^ x13(ark_o[119:112]) ^ x09(ark_o[111:104]) ^ x14(ark_o[103: 96]),

			x14(ark_o[ 95: 88]) ^ x11(ark_o[ 87: 80]) ^ x13(ark_o[ 79: 72]) ^ x09(ark_o[ 71: 64]),
			x09(ark_o[ 95: 88]) ^ x14(ark_o[ 87: 80]) ^ x11(ark_o[ 79: 72]) ^ x13(ark_o[ 71: 64]),
			x13(ark_o[ 95: 88]) ^ x09(ark_o[ 87: 80]) ^ x14(ark_o[ 79: 72]) ^ x11(ark_o[ 71: 64]),
			x11(ark_o[ 95: 88]) ^ x13(ark_o[ 87: 80]) ^ x09(ark_o[ 79: 72]) ^ x14(ark_o[ 71: 64]),

			x14(ark_o[ 63: 56]) ^ x11(ark_o[ 55: 48]) ^ x13(ark_o[ 47: 40]) ^ x09(ark_o[ 39: 32]),
			x09(ark_o[ 63: 56]) ^ x14(ark_o[ 55: 48]) ^ x11(ark_o[ 47: 40]) ^ x13(ark_o[ 39: 32]),
			x13(ark_o[ 63: 56]) ^ x09(ark_o[ 55: 48]) ^ x14(ark_o[ 47: 40]) ^ x11(ark_o[ 39: 32]),
			x11(ark_o[ 63: 56]) ^ x13(ark_o[ 55: 48]) ^ x09(ark_o[ 47: 40]) ^ x14(ark_o[ 39: 32]),

			x14(ark_o[ 31: 24]) ^ x11(ark_o[ 23: 16]) ^ x13(ark_o[ 15:  8]) ^ x09(ark_o[  7:  0]),
			x09(ark_o[ 31: 24]) ^ x14(ark_o[ 23: 16]) ^ x11(ark_o[ 15:  8]) ^ x13(ark_o[  7:  0]),
			x13(ark_o[ 31: 24]) ^ x09(ark_o[ 23: 16]) ^ x14(ark_o[ 15:  8]) ^ x11(ark_o[  7:  0]),
			x11(ark_o[ 31: 24]) ^ x13(ark_o[ 23: 16]) ^ x09(ark_o[ 15:  8]) ^ x14(ark_o[  7:  0])
		};

		if((round == round_max) || (round == 0))
			state_new = ark_o;
		else
			state_new = mxc_o;
	end
	else
	begin : subbytes_pst_encrypt
		reg [127:0] shr_o, mxc_o, ark_i;
		reg [31:0] mxc_tmp;

		shr_o = {
			sbb_o[127:120], sbb_o[ 87: 80], sbb_o[ 47: 40], sbb_o[  7:  0],
			sbb_o[ 95: 88], sbb_o[ 55: 48], sbb_o[ 15:  8], sbb_o[103: 96],
			sbb_o[ 63: 56], sbb_o[ 23: 16], sbb_o[111:104], sbb_o[ 71: 64],
			sbb_o[ 31: 24], sbb_o[119:112], sbb_o[ 79: 72], sbb_o[ 39: 32]
		};

		mxc_tmp = {
			shr_o[127:120] ^ shr_o[119:112] ^ shr_o[111:104] ^ shr_o[103: 96],
			shr_o[ 95: 88] ^ shr_o[ 87: 80] ^ shr_o[ 79: 72] ^ shr_o[ 71: 64],
			shr_o[ 63: 56] ^ shr_o[ 55: 48] ^ shr_o[ 47: 40] ^ shr_o[ 39: 32],
			shr_o[ 31: 24] ^ shr_o[ 23: 16] ^ shr_o[ 15:  8] ^ shr_o[  7:  0]
		};
		mxc_o = {
			shr_o[127:120] ^ xtime(shr_o[127:120] ^ shr_o[119:112]) ^ mxc_tmp[31:24],
			shr_o[119:112] ^ xtime(shr_o[119:112] ^ shr_o[111:104]) ^ mxc_tmp[31:24],
			shr_o[111:104] ^ xtime(shr_o[111:104] ^ shr_o[103: 96]) ^ mxc_tmp[31:24],
			shr_o[103: 96] ^ xtime(shr_o[103: 96] ^ shr_o[127:120]) ^ mxc_tmp[31:24],

			shr_o[ 95: 88] ^ xtime(shr_o[ 95: 88] ^ shr_o[ 87: 80]) ^ mxc_tmp[23:16],
			shr_o[ 87: 80] ^ xtime(shr_o[ 87: 80] ^ shr_o[ 79: 72]) ^ mxc_tmp[23:16],
			shr_o[ 79: 72] ^ xtime(shr_o[ 79: 72] ^ shr_o[ 71: 64]) ^ mxc_tmp[23:16],
			shr_o[ 71: 64] ^ xtime(shr_o[ 71: 64] ^ shr_o[ 95: 88]) ^ mxc_tmp[23:16],

			shr_o[ 63: 56] ^ xtime(shr_o[ 63: 56] ^ shr_o[ 55: 48]) ^ mxc_tmp[15: 8],
			shr_o[ 55: 48] ^ xtime(shr_o[ 55: 48] ^ shr_o[ 47: 40]) ^ mxc_tmp[15: 8],
			shr_o[ 47: 40] ^ xtime(shr_o[ 47: 40] ^ shr_o[ 39: 32]) ^ mxc_tmp[15: 8],
			shr_o[ 39: 32] ^ xtime(shr_o[ 39: 32] ^ shr_o[ 63: 56]) ^ mxc_tmp[15: 8],

			shr_o[ 31: 24] ^ xtime(shr_o[ 31: 24] ^ shr_o[ 23: 16]) ^ mxc_tmp[ 7: 0],
			shr_o[ 23: 16] ^ xtime(shr_o[ 23: 16] ^ shr_o[ 15:  8]) ^ mxc_tmp[ 7: 0],
			shr_o[ 15:  8] ^ xtime(shr_o[ 15:  8] ^ shr_o[  7:  0]) ^ mxc_tmp[ 7: 0],
			shr_o[  7:  0] ^ xtime(shr_o[  7:  0] ^ shr_o[ 31: 24]) ^ mxc_tmp[ 7: 0]
		};

		if(round == 0)
			ark_i = state;
		else if(round == round_max)
			ark_i = shr_o;
		else
			ark_i = mxc_o;

		state_new = ark_i ^ ks_val;
	end
end
`endif

`ifdef SBOX_MASKED
always @(posedge clk)
begin
	busy_o <= 0;
	if(load_i)
	begin
		fsm <= AES_KEYSCHED;
		round <= 0;
		busy_o <= 1;
		data_o <= 0;
		dec_r <= dec_i;
		// On load, the "real" plaintext enters as data_i with NO mask
		// applied yet. We seed state_m = data_i and state_r = 0 (mask
		// starts at zero) so the invariant state_m^state_r==real holds
		// from cycle one. The very first SubBytes round will mask it via
		// sbb_i_masked = sbb_i ^ mask_i, same as the original design.
		state_m <= data_i;
		state_r <= 128'b0;
	end
	else if(busy_o)
	begin
		busy_o <= 1;
		case(fsm)
		AES_KEYSCHED:
		begin
			round <= round_inc;
			if(dec_r)
			begin
				ks_mem[round] <= ks_val;
				ks <= ks_val;
				if(round == round_max)
				begin
					fsm <= AES_DECRYPT;
					round <= round_max;
				end
			end
			else
			begin
				state_m <= state_m_new;
				state_r <= state_r_new;
				if(round == round_max)
				begin
					// Final combine: real = state_m XOR state_r, ONLY here,
					// once, at the actual output -- this is the single point
					// where the mask is removed in the entire datapath.
					data_o <= state_m_new ^ state_r_new;
					busy_o <= 0;
				end
			end
		end
		AES_DECRYPT:
		begin
			ks <= ks_mem[round_dec];
			round <= round_dec;
			state_m <= state_m_new;
			state_r <= state_r_new;
			if(round == 0)
			begin
				data_o <= state_m_new ^ state_r_new;
				busy_o <= 0;
			end
		end
		endcase
	end
end
`else
always @(posedge clk)
begin
	busy_o <= 0;
	if(load_i)
	begin
		fsm <= AES_KEYSCHED;
		round <= 0;
		busy_o <= 1;
		data_o <= 0;
		dec_r <= dec_i;
		state <= data_i;
	end
	else if(busy_o)
	begin
		busy_o <= 1;
		case(fsm)
		AES_KEYSCHED:
		begin
			round <= round_inc;
			if(dec_r)
			begin
				ks_mem[round] <= ks_val;
				ks <= ks_val;
				if(round == round_max)
				begin
					fsm <= AES_DECRYPT;
					round <= round_max;
				end
			end
			else
			begin
				state <= state_new;
				if(round == round_max)
				begin
					data_o <= state_new;
					busy_o <= 0;
				end
			end
		end
		AES_DECRYPT:
		begin
			ks <= ks_mem[round_dec];
			round <= round_dec;
			state <= state_new;
			if(round == 0)
			begin
				data_o <= state_new;
				busy_o <= 0;
			end
		end
		endcase
	end
end
`endif

endmodule