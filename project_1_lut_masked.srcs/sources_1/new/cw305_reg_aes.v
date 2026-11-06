// cw305_reg_aes.v - Fixed Version

`default_nettype none
`timescale 1ns / 1ps

// Register address definitions (Replace this with actual "cw305_aes_defines.v" file if available)
`define REG_CLKSETTINGS     8'h01
`define REG_USER_LED        8'h02
`define REG_CRYPT_TYPE      8'h03
`define REG_CRYPT_REV       8'h04
`define REG_IDENTIFY        8'h05
`define REG_CRYPT_GO        8'h06
`define REG_CRYPT_KEY       8'h07
`define REG_CRYPT_TEXTIN    8'h08
`define REG_CRYPT_CIPHERIN  8'h09
`define REG_CRYPT_TEXTOUT   8'h0A
`define REG_CRYPT_CIPHEROUT 8'h0B
`define REG_BUILDTIME       8'h0C

module cw305_reg_aes #(
   parameter pADDR_WIDTH = 21,
   parameter pBYTECNT_SIZE = 7,
   parameter pDONE_EDGE_SENSITIVE = 1,
   parameter pPT_WIDTH = 128,
   parameter pCT_WIDTH = 128,
   parameter pKEY_WIDTH = 128,
   parameter pCRYPT_TYPE = 2,
   parameter pCRYPT_REV = 5,
   parameter pIDENTIFY = 8'h2e
)(
   input  wire                                  usb_clk,
   input  wire                                  crypto_clk,
   input  wire                                  reset_i,
   input  wire [pADDR_WIDTH-pBYTECNT_SIZE-1:0]  reg_address,
   input  wire [pBYTECNT_SIZE-1:0]              reg_bytecnt,
   output reg  [7:0]                            read_data,
   input  wire [7:0]                            write_data,
   input  wire                                  reg_read,
   input  wire                                  reg_write,
   input  wire                                  reg_addrvalid,
   input  wire                                  exttrigger_in,
   input  wire [pPT_WIDTH-1:0]                  I_textout,
   input  wire [pCT_WIDTH-1:0]                  I_cipherout,
   input  wire                                  I_ready,
   input  wire                                  I_done,
   input  wire                                  I_busy,
   output reg  [4:0]                            O_clksettings,
   output reg                                   O_user_led,
   output wire [pKEY_WIDTH-1:0]                 O_key,
   output wire [pPT_WIDTH-1:0]                  O_textin,
   output wire [pCT_WIDTH-1:0]                  O_cipherin,
   output wire                                  O_start
);

   reg  [7:0]                   reg_read_data;
   reg  [pCT_WIDTH-1:0]         reg_crypt_cipherin;
   reg  [pKEY_WIDTH-1:0]        reg_crypt_key;
   reg  [pPT_WIDTH-1:0]         reg_crypt_textin;
   reg  [pPT_WIDTH-1:0]         reg_crypt_textout;
   reg  [pCT_WIDTH-1:0]         reg_crypt_cipherout;
   reg                          reg_crypt_go_pulse;
   wire                         reg_crypt_go_pulse_crypt;
   reg                          busy_usb;
   reg                          done_r;
   wire                         done_pulse;
   wire                         crypt_go_pulse;
   reg                          go_r, go;
   wire [31:0]                  buildtime;

   (* ASYNC_REG = "TRUE" *) reg  [pKEY_WIDTH-1:0] reg_crypt_key_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [pPT_WIDTH-1:0] reg_crypt_textin_crypt;
   (* ASYNC_REG = "TRUE" *) reg  [pPT_WIDTH-1:0] reg_crypt_textout_usb;
   (* ASYNC_REG = "TRUE" *) reg  [pCT_WIDTH-1:0] reg_crypt_cipherout_usb;
   (* ASYNC_REG = "TRUE" *) reg  [1:0] go_pipe, busy_pipe;

   always @(posedge crypto_clk)
       done_r <= I_done & pDONE_EDGE_SENSITIVE;
   assign done_pulse = I_done & ~done_r;

   always @(posedge crypto_clk) begin
       if (done_pulse) begin
           reg_crypt_cipherout <= I_cipherout;
           reg_crypt_textout   <= I_textout;
       end
   end

   always @(posedge usb_clk) begin
       reg_crypt_cipherout_usb <= reg_crypt_cipherout;
       reg_crypt_textout_usb   <= reg_crypt_textout;
   end

   always @(posedge crypto_clk) begin
       reg_crypt_key_crypt <= reg_crypt_key;
       reg_crypt_textin_crypt <= reg_crypt_textin;
   end

   assign O_textin = reg_crypt_textin_crypt;
   assign O_key = reg_crypt_key_crypt;
   assign O_cipherin = reg_crypt_cipherin;
   assign O_start = crypt_go_pulse || reg_crypt_go_pulse_crypt;

   always @(*) begin
      if (reg_addrvalid && reg_read) begin
         case (reg_address)
            `REG_CLKSETTINGS: reg_read_data = O_clksettings;
            `REG_USER_LED:   reg_read_data = O_user_led;
            `REG_CRYPT_TYPE: reg_read_data = pCRYPT_TYPE;
            `REG_CRYPT_REV:  reg_read_data = pCRYPT_REV;
            `REG_IDENTIFY:   reg_read_data = pIDENTIFY;
            `REG_CRYPT_GO:   reg_read_data = busy_usb;
            `REG_CRYPT_KEY:  reg_read_data = reg_crypt_key[reg_bytecnt*8 +: 8];
            `REG_CRYPT_TEXTIN: reg_read_data = reg_crypt_textin[reg_bytecnt*8 +: 8];
            `REG_CRYPT_CIPHERIN: reg_read_data = reg_crypt_cipherin[reg_bytecnt*8 +: 8];
            `REG_CRYPT_TEXTOUT: reg_read_data = reg_crypt_textout_usb[reg_bytecnt*8 +: 8];
            `REG_CRYPT_CIPHEROUT: reg_read_data = reg_crypt_cipherout_usb[reg_bytecnt*8 +: 8];
            `REG_BUILDTIME:  reg_read_data = buildtime[reg_bytecnt*8 +: 8];
            default:         reg_read_data = 0;
         endcase
      end else begin
         reg_read_data = 0;
      end
   end

   always @(posedge usb_clk)
      read_data <= reg_read_data;

   always @(posedge usb_clk) begin
      if (reset_i) begin
         O_clksettings <= 0;
         O_user_led <= 0;
         reg_crypt_go_pulse <= 1'b0;
      end else begin
         if (reg_addrvalid && reg_write) begin
            case (reg_address)
               `REG_CLKSETTINGS: O_clksettings <= write_data;
               `REG_USER_LED: O_user_led <= write_data;
               `REG_CRYPT_TEXTIN: reg_crypt_textin[reg_bytecnt*8 +: 8] <= write_data;
               `REG_CRYPT_CIPHERIN: reg_crypt_cipherin[reg_bytecnt*8 +: 8] <= write_data;
               `REG_CRYPT_KEY: reg_crypt_key[reg_bytecnt*8 +: 8] <= write_data;
            endcase
         end
         reg_crypt_go_pulse <= (reg_addrvalid && reg_write && (reg_address == `REG_CRYPT_GO));
      end
   end

   always @(posedge crypto_clk)
      {go_r, go, go_pipe} <= {go, go_pipe, exttrigger_in};
   assign crypt_go_pulse = go & !go_r;

   cdc_pulse U_go_pulse (
      .reset_i       (reset_i),
      .src_clk       (usb_clk),
      .src_pulse     (reg_crypt_go_pulse),
      .dst_clk       (crypto_clk),
      .dst_pulse     (reg_crypt_go_pulse_crypt)
   );

   always @(posedge usb_clk)
      {busy_usb, busy_pipe} <= {busy_pipe, I_busy};

   assign buildtime = 32'h00000000; // Replace with dynamic timestamp logic or include file if needed

endmodule

`default_nettype wire
