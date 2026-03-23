// =============================================================================
// Copyright (c) 2026 Lumees Lab / Hasan Kurşun
// SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
//
// Licensed under the Apache License 2.0 with Commons Clause restriction.
// You may use this file freely for non-commercial purposes (academic,
// research, hobby, education, personal projects).
//
// COMMERCIAL USE requires a separate license from Lumees Lab.
// Contact: info@lumeeslab.com · https://lumeeslab.com
// =============================================================================
// =============================================================================
// AES IP - Package
// =============================================================================
// Defines types, constants, and all AES primitive functions for use across
// the entire IP hierarchy.
//
// Data format:
//   state_t  : 4×4 byte matrix, state[row][col], column-major fill from
//              128-bit words (byte 0 = MSB → state[0][0], byte 1 → state[1][0])
//
// Key length is a compile-time parameter (KEY_BITS ∈ {128, 192, 256}).
// Changing KEY_BITS automatically adjusts N_ROUNDS and pipeline depth.
//
// ROUND_KEYS_T holds all pre-expanded round keys for the selected key length.
// =============================================================================

package aes_pkg;

  // ---------------------------------------------------------------------------
  // Global parameters — override AES_KEY_BITS define to select AES-128/192/256
  //   Simulator/synthesiser: pass +define+AES_KEY_BITS=192 (or 256)
  // ---------------------------------------------------------------------------
`ifndef AES_KEY_BITS
  `define AES_KEY_BITS 128
`endif
  parameter int KEY_BITS   = `AES_KEY_BITS;   // 128 | 192 | 256
  parameter int DATA_BITS  = 128;   // AES block is always 128-bit

  // Derived
  parameter int N_ROUNDS   = (KEY_BITS == 128) ? 10 :
                             (KEY_BITS == 192) ? 12 : 14;
  parameter int N_KEY_WORDS = KEY_BITS / 32;                  // 4 | 6 | 8
  parameter int N_ROUND_KEYS = N_ROUNDS + 1;                  // 11 | 13 | 15
  parameter int TOTAL_KEY_WORDS = 4 * N_ROUND_KEYS;           // 44 | 52 | 60

  // IP versioning
  parameter logic [31:0] IP_VERSION  = 32'h0001_0000;
  parameter int          PIPE_LAT    = N_ROUNDS + 1;          // pipeline latency (cycles)

  // ---------------------------------------------------------------------------
  // Mode / Direction enums
  // ---------------------------------------------------------------------------
  typedef enum logic [1:0] {
    ECB = 2'b00,
    CBC = 2'b01,
    CTR = 2'b10
  } mode_t;

  typedef enum logic {
    ENCRYPT = 1'b0,
    DECRYPT = 1'b1
  } dir_t;

  // ---------------------------------------------------------------------------
  // AES state type: 4×4 matrix of bytes, [row][col]
  // ---------------------------------------------------------------------------
  typedef logic [0:3][0:3][7:0] state_t;

  // ---------------------------------------------------------------------------
  // Pipeline data bundle
  // ---------------------------------------------------------------------------
  typedef struct packed {
    logic        valid;
    logic [7:0]  tag;
    logic [127:0] data;   // raw 128-bit block (in: plaintext/CT, out: CT/plaintext)
  } aes_pipe_t;

  // ---------------------------------------------------------------------------
  // AES Forward S-box (FIPS 197, Figure 7)
  // ---------------------------------------------------------------------------
  function automatic logic [7:0] sbox_fwd(input logic [7:0] x);
    logic [7:0] lut [0:255];
    lut[  0]=8'h63; lut[  1]=8'h7c; lut[  2]=8'h77; lut[  3]=8'h7b;
    lut[  4]=8'hf2; lut[  5]=8'h6b; lut[  6]=8'h6f; lut[  7]=8'hc5;
    lut[  8]=8'h30; lut[  9]=8'h01; lut[ 10]=8'h67; lut[ 11]=8'h2b;
    lut[ 12]=8'hfe; lut[ 13]=8'hd7; lut[ 14]=8'hab; lut[ 15]=8'h76;
    lut[ 16]=8'hca; lut[ 17]=8'h82; lut[ 18]=8'hc9; lut[ 19]=8'h7d;
    lut[ 20]=8'hfa; lut[ 21]=8'h59; lut[ 22]=8'h47; lut[ 23]=8'hf0;
    lut[ 24]=8'had; lut[ 25]=8'hd4; lut[ 26]=8'ha2; lut[ 27]=8'haf;
    lut[ 28]=8'h9c; lut[ 29]=8'ha4; lut[ 30]=8'h72; lut[ 31]=8'hc0;
    lut[ 32]=8'hb7; lut[ 33]=8'hfd; lut[ 34]=8'h93; lut[ 35]=8'h26;
    lut[ 36]=8'h36; lut[ 37]=8'h3f; lut[ 38]=8'hf7; lut[ 39]=8'hcc;
    lut[ 40]=8'h34; lut[ 41]=8'ha5; lut[ 42]=8'he5; lut[ 43]=8'hf1;
    lut[ 44]=8'h71; lut[ 45]=8'hd8; lut[ 46]=8'h31; lut[ 47]=8'h15;
    lut[ 48]=8'h04; lut[ 49]=8'hc7; lut[ 50]=8'h23; lut[ 51]=8'hc3;
    lut[ 52]=8'h18; lut[ 53]=8'h96; lut[ 54]=8'h05; lut[ 55]=8'h9a;
    lut[ 56]=8'h07; lut[ 57]=8'h12; lut[ 58]=8'h80; lut[ 59]=8'he2;
    lut[ 60]=8'heb; lut[ 61]=8'h27; lut[ 62]=8'hb2; lut[ 63]=8'h75;
    lut[ 64]=8'h09; lut[ 65]=8'h83; lut[ 66]=8'h2c; lut[ 67]=8'h1a;
    lut[ 68]=8'h1b; lut[ 69]=8'h6e; lut[ 70]=8'h5a; lut[ 71]=8'ha0;
    lut[ 72]=8'h52; lut[ 73]=8'h3b; lut[ 74]=8'hd6; lut[ 75]=8'hb3;
    lut[ 76]=8'h29; lut[ 77]=8'he3; lut[ 78]=8'h2f; lut[ 79]=8'h84;
    lut[ 80]=8'h53; lut[ 81]=8'hd1; lut[ 82]=8'h00; lut[ 83]=8'hed;
    lut[ 84]=8'h20; lut[ 85]=8'hfc; lut[ 86]=8'hb1; lut[ 87]=8'h5b;
    lut[ 88]=8'h6a; lut[ 89]=8'hcb; lut[ 90]=8'hbe; lut[ 91]=8'h39;
    lut[ 92]=8'h4a; lut[ 93]=8'h4c; lut[ 94]=8'h58; lut[ 95]=8'hcf;
    lut[ 96]=8'hd0; lut[ 97]=8'hef; lut[ 98]=8'haa; lut[ 99]=8'hfb;
    lut[100]=8'h43; lut[101]=8'h4d; lut[102]=8'h33; lut[103]=8'h85;
    lut[104]=8'h45; lut[105]=8'hf9; lut[106]=8'h02; lut[107]=8'h7f;
    lut[108]=8'h50; lut[109]=8'h3c; lut[110]=8'h9f; lut[111]=8'ha8;
    lut[112]=8'h51; lut[113]=8'ha3; lut[114]=8'h40; lut[115]=8'h8f;
    lut[116]=8'h92; lut[117]=8'h9d; lut[118]=8'h38; lut[119]=8'hf5;
    lut[120]=8'hbc; lut[121]=8'hb6; lut[122]=8'hda; lut[123]=8'h21;
    lut[124]=8'h10; lut[125]=8'hff; lut[126]=8'hf3; lut[127]=8'hd2;
    lut[128]=8'hcd; lut[129]=8'h0c; lut[130]=8'h13; lut[131]=8'hec;
    lut[132]=8'h5f; lut[133]=8'h97; lut[134]=8'h44; lut[135]=8'h17;
    lut[136]=8'hc4; lut[137]=8'ha7; lut[138]=8'h7e; lut[139]=8'h3d;
    lut[140]=8'h64; lut[141]=8'h5d; lut[142]=8'h19; lut[143]=8'h73;
    lut[144]=8'h60; lut[145]=8'h81; lut[146]=8'h4f; lut[147]=8'hdc;
    lut[148]=8'h22; lut[149]=8'h2a; lut[150]=8'h90; lut[151]=8'h88;
    lut[152]=8'h46; lut[153]=8'hee; lut[154]=8'hb8; lut[155]=8'h14;
    lut[156]=8'hde; lut[157]=8'h5e; lut[158]=8'h0b; lut[159]=8'hdb;
    lut[160]=8'he0; lut[161]=8'h32; lut[162]=8'h3a; lut[163]=8'h0a;
    lut[164]=8'h49; lut[165]=8'h06; lut[166]=8'h24; lut[167]=8'h5c;
    lut[168]=8'hc2; lut[169]=8'hd3; lut[170]=8'hac; lut[171]=8'h62;
    lut[172]=8'h91; lut[173]=8'h95; lut[174]=8'he4; lut[175]=8'h79;
    lut[176]=8'he7; lut[177]=8'hc8; lut[178]=8'h37; lut[179]=8'h6d;
    lut[180]=8'h8d; lut[181]=8'hd5; lut[182]=8'h4e; lut[183]=8'ha9;
    lut[184]=8'h6c; lut[185]=8'h56; lut[186]=8'hf4; lut[187]=8'hea;
    lut[188]=8'h65; lut[189]=8'h7a; lut[190]=8'hae; lut[191]=8'h08;
    lut[192]=8'hba; lut[193]=8'h78; lut[194]=8'h25; lut[195]=8'h2e;
    lut[196]=8'h1c; lut[197]=8'ha6; lut[198]=8'hb4; lut[199]=8'hc6;
    lut[200]=8'he8; lut[201]=8'hdd; lut[202]=8'h74; lut[203]=8'h1f;
    lut[204]=8'h4b; lut[205]=8'hbd; lut[206]=8'h8b; lut[207]=8'h8a;
    lut[208]=8'h70; lut[209]=8'h3e; lut[210]=8'hb5; lut[211]=8'h66;
    lut[212]=8'h48; lut[213]=8'h03; lut[214]=8'hf6; lut[215]=8'h0e;
    lut[216]=8'h61; lut[217]=8'h35; lut[218]=8'h57; lut[219]=8'hb9;
    lut[220]=8'h86; lut[221]=8'hc1; lut[222]=8'h1d; lut[223]=8'h9e;
    lut[224]=8'he1; lut[225]=8'hf8; lut[226]=8'h98; lut[227]=8'h11;
    lut[228]=8'h69; lut[229]=8'hd9; lut[230]=8'h8e; lut[231]=8'h94;
    lut[232]=8'h9b; lut[233]=8'h1e; lut[234]=8'h87; lut[235]=8'he9;
    lut[236]=8'hce; lut[237]=8'h55; lut[238]=8'h28; lut[239]=8'hdf;
    lut[240]=8'h8c; lut[241]=8'ha1; lut[242]=8'h89; lut[243]=8'h0d;
    lut[244]=8'hbf; lut[245]=8'he6; lut[246]=8'h42; lut[247]=8'h68;
    lut[248]=8'h41; lut[249]=8'h99; lut[250]=8'h2d; lut[251]=8'h0f;
    lut[252]=8'hb0; lut[253]=8'h54; lut[254]=8'hbb; lut[255]=8'h16;
    return lut[x];
  endfunction

  // ---------------------------------------------------------------------------
  // AES Inverse S-box (FIPS 197, Figure 14)
  // ---------------------------------------------------------------------------
  function automatic logic [7:0] sbox_inv(input logic [7:0] x);
    logic [7:0] lut [0:255];
    lut[  0]=8'h52; lut[  1]=8'h09; lut[  2]=8'h6a; lut[  3]=8'hd5;
    lut[  4]=8'h30; lut[  5]=8'h36; lut[  6]=8'ha5; lut[  7]=8'h38;
    lut[  8]=8'hbf; lut[  9]=8'h40; lut[ 10]=8'ha3; lut[ 11]=8'h9e;
    lut[ 12]=8'h81; lut[ 13]=8'hf3; lut[ 14]=8'hd7; lut[ 15]=8'hfb;
    lut[ 16]=8'h7c; lut[ 17]=8'he3; lut[ 18]=8'h39; lut[ 19]=8'h82;
    lut[ 20]=8'h9b; lut[ 21]=8'h2f; lut[ 22]=8'hff; lut[ 23]=8'h87;
    lut[ 24]=8'h34; lut[ 25]=8'h8e; lut[ 26]=8'h43; lut[ 27]=8'h44;
    lut[ 28]=8'hc4; lut[ 29]=8'hde; lut[ 30]=8'he9; lut[ 31]=8'hcb;
    lut[ 32]=8'h54; lut[ 33]=8'h7b; lut[ 34]=8'h94; lut[ 35]=8'h32;
    lut[ 36]=8'ha6; lut[ 37]=8'hc2; lut[ 38]=8'h23; lut[ 39]=8'h3d;
    lut[ 40]=8'hee; lut[ 41]=8'h4c; lut[ 42]=8'h95; lut[ 43]=8'h0b;
    lut[ 44]=8'h42; lut[ 45]=8'hfa; lut[ 46]=8'hc3; lut[ 47]=8'h4e;
    lut[ 48]=8'h08; lut[ 49]=8'h2e; lut[ 50]=8'ha1; lut[ 51]=8'h66;
    lut[ 52]=8'h28; lut[ 53]=8'hd9; lut[ 54]=8'h24; lut[ 55]=8'hb2;
    lut[ 56]=8'h76; lut[ 57]=8'h5b; lut[ 58]=8'ha2; lut[ 59]=8'h49;
    lut[ 60]=8'h6d; lut[ 61]=8'h8b; lut[ 62]=8'hd1; lut[ 63]=8'h25;
    lut[ 64]=8'h72; lut[ 65]=8'hf8; lut[ 66]=8'hf6; lut[ 67]=8'h64;
    lut[ 68]=8'h86; lut[ 69]=8'h68; lut[ 70]=8'h98; lut[ 71]=8'h16;
    lut[ 72]=8'hd4; lut[ 73]=8'ha4; lut[ 74]=8'h5c; lut[ 75]=8'hcc;
    lut[ 76]=8'h5d; lut[ 77]=8'h65; lut[ 78]=8'hb6; lut[ 79]=8'h92;
    lut[ 80]=8'h6c; lut[ 81]=8'h70; lut[ 82]=8'h48; lut[ 83]=8'h50;
    lut[ 84]=8'hfd; lut[ 85]=8'hed; lut[ 86]=8'hb9; lut[ 87]=8'hda;
    lut[ 88]=8'h5e; lut[ 89]=8'h15; lut[ 90]=8'h46; lut[ 91]=8'h57;
    lut[ 92]=8'ha7; lut[ 93]=8'h8d; lut[ 94]=8'h9d; lut[ 95]=8'h84;
    lut[ 96]=8'h90; lut[ 97]=8'hd8; lut[ 98]=8'hab; lut[ 99]=8'h00;
    lut[100]=8'h8c; lut[101]=8'hbc; lut[102]=8'hd3; lut[103]=8'h0a;
    lut[104]=8'hf7; lut[105]=8'he4; lut[106]=8'h58; lut[107]=8'h05;
    lut[108]=8'hb8; lut[109]=8'hb3; lut[110]=8'h45; lut[111]=8'h06;
    lut[112]=8'hd0; lut[113]=8'h2c; lut[114]=8'h1e; lut[115]=8'h8f;
    lut[116]=8'hca; lut[117]=8'h3f; lut[118]=8'h0f; lut[119]=8'h02;
    lut[120]=8'hc1; lut[121]=8'haf; lut[122]=8'hbd; lut[123]=8'h03;
    lut[124]=8'h01; lut[125]=8'h13; lut[126]=8'h8a; lut[127]=8'h6b;
    lut[128]=8'h3a; lut[129]=8'h91; lut[130]=8'h11; lut[131]=8'h41;
    lut[132]=8'h4f; lut[133]=8'h67; lut[134]=8'hdc; lut[135]=8'hea;
    lut[136]=8'h97; lut[137]=8'hf2; lut[138]=8'hcf; lut[139]=8'hce;
    lut[140]=8'hf0; lut[141]=8'hb4; lut[142]=8'he6; lut[143]=8'h73;
    lut[144]=8'h96; lut[145]=8'hac; lut[146]=8'h74; lut[147]=8'h22;
    lut[148]=8'he7; lut[149]=8'had; lut[150]=8'h35; lut[151]=8'h85;
    lut[152]=8'he2; lut[153]=8'hf9; lut[154]=8'h37; lut[155]=8'he8;
    lut[156]=8'h1c; lut[157]=8'h75; lut[158]=8'hdf; lut[159]=8'h6e;
    lut[160]=8'h47; lut[161]=8'hf1; lut[162]=8'h1a; lut[163]=8'h71;
    lut[164]=8'h1d; lut[165]=8'h29; lut[166]=8'hc5; lut[167]=8'h89;
    lut[168]=8'h6f; lut[169]=8'hb7; lut[170]=8'h62; lut[171]=8'h0e;
    lut[172]=8'haa; lut[173]=8'h18; lut[174]=8'hbe; lut[175]=8'h1b;
    lut[176]=8'hfc; lut[177]=8'h56; lut[178]=8'h3e; lut[179]=8'h4b;
    lut[180]=8'hc6; lut[181]=8'hd2; lut[182]=8'h79; lut[183]=8'h20;
    lut[184]=8'h9a; lut[185]=8'hdb; lut[186]=8'hc0; lut[187]=8'hfe;
    lut[188]=8'h78; lut[189]=8'hcd; lut[190]=8'h5a; lut[191]=8'hf4;
    lut[192]=8'h1f; lut[193]=8'hdd; lut[194]=8'ha8; lut[195]=8'h33;
    lut[196]=8'h88; lut[197]=8'h07; lut[198]=8'hc7; lut[199]=8'h31;
    lut[200]=8'hb1; lut[201]=8'h12; lut[202]=8'h10; lut[203]=8'h59;
    lut[204]=8'h27; lut[205]=8'h80; lut[206]=8'hec; lut[207]=8'h5f;
    lut[208]=8'h60; lut[209]=8'h51; lut[210]=8'h7f; lut[211]=8'ha9;
    lut[212]=8'h19; lut[213]=8'hb5; lut[214]=8'h4a; lut[215]=8'h0d;
    lut[216]=8'h2d; lut[217]=8'he5; lut[218]=8'h7a; lut[219]=8'h9f;
    lut[220]=8'h93; lut[221]=8'hc9; lut[222]=8'h9c; lut[223]=8'hef;
    lut[224]=8'ha0; lut[225]=8'he0; lut[226]=8'h3b; lut[227]=8'h4d;
    lut[228]=8'hae; lut[229]=8'h2a; lut[230]=8'hf5; lut[231]=8'hb0;
    lut[232]=8'hc8; lut[233]=8'heb; lut[234]=8'hbb; lut[235]=8'h3c;
    lut[236]=8'h83; lut[237]=8'h53; lut[238]=8'h99; lut[239]=8'h61;
    lut[240]=8'h17; lut[241]=8'h2b; lut[242]=8'h04; lut[243]=8'h7e;
    lut[244]=8'hba; lut[245]=8'h77; lut[246]=8'hd6; lut[247]=8'h26;
    lut[248]=8'he1; lut[249]=8'h69; lut[250]=8'h14; lut[251]=8'h63;
    lut[252]=8'h55; lut[253]=8'h21; lut[254]=8'h0c; lut[255]=8'h7d;
    return lut[x];
  endfunction

  // ---------------------------------------------------------------------------
  // GF(2^8) arithmetic — irreducible polynomial x^8+x^4+x^3+x+1 (0x11b)
  // ---------------------------------------------------------------------------
  function automatic logic [7:0] xtime(input logic [7:0] b);
    return {b[6:0], 1'b0} ^ (b[7] ? 8'h1b : 8'h00);
  endfunction

  function automatic logic [7:0] gmul(input logic [7:0] b, input logic [7:0] m);
    logic [7:0] result, p;
    result = 8'h00;
    p = b;
    for (int i = 0; i < 8; i++) begin
      if (m[i]) result ^= p;
      p = xtime(p);
    end
    return result;
  endfunction

  // ---------------------------------------------------------------------------
  // Round constant Rcon (1-indexed, Rcon[0] unused)
  // ---------------------------------------------------------------------------
  function automatic logic [7:0] rcon(input int i);
    // Precomputed Rcon[1..14] — avoids variable-bound loop (Vivado Synth 8-3380)
    logic [7:0] lut [1:14];
    lut[1]  = 8'h01; lut[2]  = 8'h02; lut[3]  = 8'h04; lut[4]  = 8'h08;
    lut[5]  = 8'h10; lut[6]  = 8'h20; lut[7]  = 8'h40; lut[8]  = 8'h80;
    lut[9]  = 8'h1b; lut[10] = 8'h36; lut[11] = 8'h6c; lut[12] = 8'hd8;
    lut[13] = 8'hab; lut[14] = 8'h4d;
    return lut[i];
  endfunction

  // ---------------------------------------------------------------------------
  // State packing/unpacking helpers
  // Byte 0 of 128-bit (MSB) → state[0][0], byte 1 → state[1][0], column-major
  // ---------------------------------------------------------------------------
  function automatic state_t bytes_to_state(input logic [127:0] d);
    state_t s;
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++)
        s[r][c] = d[127 - 8*(c*4 + r) -: 8];
    return s;
  endfunction

  function automatic logic [127:0] state_to_bytes(input state_t s);
    logic [127:0] d;
    for (int c = 0; c < 4; c++)
      for (int r = 0; r < 4; r++)
        d[127 - 8*(c*4 + r) -: 8] = s[r][c];
    return d;
  endfunction

  // ---------------------------------------------------------------------------
  // AES round operations (encryption)
  // ---------------------------------------------------------------------------
  function automatic state_t sub_bytes_enc(input state_t s);
    state_t r;
    for (int row = 0; row < 4; row++)
      for (int col = 0; col < 4; col++)
        r[row][col] = sbox_fwd(s[row][col]);
    return r;
  endfunction

  function automatic state_t shift_rows_enc(input state_t s);
    state_t r;
    for (int col = 0; col < 4; col++) r[0][col] = s[0][(col    ) % 4];
    for (int col = 0; col < 4; col++) r[1][col] = s[1][(col + 1) % 4];
    for (int col = 0; col < 4; col++) r[2][col] = s[2][(col + 2) % 4];
    for (int col = 0; col < 4; col++) r[3][col] = s[3][(col + 3) % 4];
    return r;
  endfunction

  function automatic state_t mix_columns_enc(input state_t s);
    state_t r;
    for (int c = 0; c < 4; c++) begin
      r[0][c] = gmul(s[0][c],8'h02) ^ gmul(s[1][c],8'h03) ^ s[2][c]              ^ s[3][c];
      r[1][c] = s[0][c]             ^ gmul(s[1][c],8'h02) ^ gmul(s[2][c],8'h03)  ^ s[3][c];
      r[2][c] = s[0][c]             ^ s[1][c]             ^ gmul(s[2][c],8'h02)  ^ gmul(s[3][c],8'h03);
      r[3][c] = gmul(s[0][c],8'h03) ^ s[1][c]             ^ s[2][c]              ^ gmul(s[3][c],8'h02);
    end
    return r;
  endfunction

  function automatic state_t add_round_key(input state_t s, input logic [127:0] rk);
    return bytes_to_state(state_to_bytes(s) ^ rk);
  endfunction

  // Full encryption round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
  function automatic logic [127:0] enc_round(input logic [127:0] data, input logic [127:0] rk);
    state_t s;
    s = bytes_to_state(data);
    s = sub_bytes_enc(s);
    s = shift_rows_enc(s);
    s = mix_columns_enc(s);
    s = add_round_key(s, rk);
    return state_to_bytes(s);
  endfunction

  // Final encryption round (no MixColumns)
  function automatic logic [127:0] enc_final_round(input logic [127:0] data, input logic [127:0] rk);
    state_t s;
    s = bytes_to_state(data);
    s = sub_bytes_enc(s);
    s = shift_rows_enc(s);
    s = add_round_key(s, rk);
    return state_to_bytes(s);
  endfunction

  // ---------------------------------------------------------------------------
  // AES round operations (decryption — standard inverse cipher)
  // ---------------------------------------------------------------------------
  function automatic state_t sub_bytes_dec(input state_t s);
    state_t r;
    for (int row = 0; row < 4; row++)
      for (int col = 0; col < 4; col++)
        r[row][col] = sbox_inv(s[row][col]);
    return r;
  endfunction

  function automatic state_t shift_rows_dec(input state_t s);
    state_t r;
    for (int col = 0; col < 4; col++) r[0][col] = s[0][(col    ) % 4];
    for (int col = 0; col < 4; col++) r[1][col] = s[1][(col + 3) % 4];  // right 1
    for (int col = 0; col < 4; col++) r[2][col] = s[2][(col + 2) % 4];  // right 2
    for (int col = 0; col < 4; col++) r[3][col] = s[3][(col + 1) % 4];  // right 3
    return r;
  endfunction

  function automatic state_t mix_columns_dec(input state_t s);
    state_t r;
    for (int c = 0; c < 4; c++) begin
      r[0][c] = gmul(s[0][c],8'h0e) ^ gmul(s[1][c],8'h0b) ^ gmul(s[2][c],8'h0d) ^ gmul(s[3][c],8'h09);
      r[1][c] = gmul(s[0][c],8'h09) ^ gmul(s[1][c],8'h0e) ^ gmul(s[2][c],8'h0b) ^ gmul(s[3][c],8'h0d);
      r[2][c] = gmul(s[0][c],8'h0d) ^ gmul(s[1][c],8'h09) ^ gmul(s[2][c],8'h0e) ^ gmul(s[3][c],8'h0b);
      r[3][c] = gmul(s[0][c],8'h0b) ^ gmul(s[1][c],8'h0d) ^ gmul(s[2][c],8'h09) ^ gmul(s[3][c],8'h0e);
    end
    return r;
  endfunction

  // Full decryption round (InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns)
  function automatic logic [127:0] dec_round(input logic [127:0] data, input logic [127:0] rk);
    state_t s;
    s = bytes_to_state(data);
    s = shift_rows_dec(s);
    s = sub_bytes_dec(s);
    s = add_round_key(s, rk);
    s = mix_columns_dec(s);
    return state_to_bytes(s);
  endfunction

  // Final decryption round (no InvMixColumns)
  function automatic logic [127:0] dec_final_round(input logic [127:0] data, input logic [127:0] rk);
    state_t s;
    s = bytes_to_state(data);
    s = shift_rows_dec(s);
    s = sub_bytes_dec(s);
    s = add_round_key(s, rk);
    return state_to_bytes(s);
  endfunction

endpackage : aes_pkg
