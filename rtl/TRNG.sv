module LFSR #(parameter DATASIZE = 32,
              parameter ENCRYPT = 32'hB0081355)(input p_load, run, clk, 
             input [DATASIZE-1:0] value,
             output [DATASIZE-1:0] out);
  
  reg [DATASIZE-1:0] encryption = ENCRYPT;
  reg [DATASIZE-1:0] lfsr;
  reg xor_shift;
  integer i;
    
  always @(*) begin
    xor_shift = 0;
    if (run) begin
      for (i = 0;i<DATASIZE; i = i+1) begin
     	 xor_shift = xor_shift^(lfsr[i]&encryption[i]);
    	end
    end
    
  end
  
  always @(posedge clk) begin
    if (p_load) begin
      lfsr<=value;
    end
    else begin
      if (run) begin
        lfsr<={xor_shift, lfsr[DATASIZE-1:1]};
      end
      else begin
        lfsr<=lfsr;
      end
    end
  end
  assign out = lfsr;
endmodule

module controller #(parameter DATASIZE = 8) (
    input wire                  load, 
    input wire                  clk,
    input wire [DATASIZE-1:0]   counter_val,
    output reg                  run, 
    output reg                  p_load, 
  output reg                  output_load );

  localparam IDLE    = 2'b00, 
             LOAD    = 2'b01, 
             PROCESS = 2'b10;

  reg [1:0]          state = IDLE; 
  reg [1:0]          new_state;
  reg [DATASIZE-1:0] count; 

  always @(*) begin
    case(state)
      IDLE: begin
        if(load) begin
          new_state = LOAD;
        end
        else begin
          new_state = IDLE;
        end
      end

      LOAD: begin
        new_state = PROCESS;
      end

      PROCESS: begin
        if(count > 0) begin 
          new_state = PROCESS;
        end
        else begin
          new_state = IDLE;
        end
      end
      
      default: new_state = IDLE;
    endcase
  end

  always @(posedge clk) begin
    state <= new_state; 
    
    p_load      <= 1'b0;
    run         <= 1'b0;
    output_load <= 1'b0;

    if (state == LOAD) begin
      count  <= counter_val; 
      p_load <= 1'b1;
    end 
    else if (state == PROCESS) begin
      if (count > 0) begin
        count <= count - 1'b1; 
        run   <= 1'b1; 
      end
      else if (count == 0) begin
        output_load<=1;
      end
    end
    
  end
endmodule

module top_module #(parameter DATASIZE = 32, 
                   parameter COUNTSIZE = 8,
                   parameter ENCRYPT = 32'hB0081355) (input clk, load,
                                              input [DATASIZE-1:0] lfsr_load,
                                             input [COUNTSIZE-1:0] count_load,
                                              output reg [DATASIZE-1:0] out);
  reg out_en;
  wire run, p_load;
  wire [DATASIZE-1:0] out_wire;
  
  LFSR  #(.DATASIZE(DATASIZE),.ENCRYPT(ENCRYPT)) l0(.p_load(p_load),.run(run),.clk(clk),.value(lfsr_load),.out(out_wire));
  controller #(.DATASIZE(COUNTSIZE)) c0(.load(load),.clk(clk),.counter_val(count_load),.run(run),.p_load(p_load),.output_load(out_en));
  always @(posedge clk) begin
    if (out_en) begin
      out<=out_wire;
    end
  end
  
endmodule