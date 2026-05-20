module test #(parameter DATASIZE = 32, 
             parameter COUNTSIZE = 8,
             parameter ENCRYPT = 32'hB0081355);
  reg [DATASIZE-1:0] lfsr_load;
  reg [COUNTSIZE-1:0] count_load;
  reg clk=0;
  reg load;
  wire [DATASIZE-1:0] out;
  
  top_module #(.DATASIZE(DATASIZE), .COUNTSIZE(COUNTSIZE), .ENCRYPT(ENCRYPT)) t0(.clk(clk), .load(load), .lfsr_load(lfsr_load), .count_load(count_load), .out(out));
  
  always begin
    #1 clk<=~clk;
  end
  
  initial begin
    $dumpfile("dump.vcd");
    $dumpvars(1);
    
    lfsr_load = 32'h26742659;
    count_load = 8'h10;
    
    #6 load = 1;
    
    #2 load = 0;
    
    #80 lfsr_load = 32'h26372691;
    count_load = 8'h00;
    
    #10 load = 1;
    
    #2 load = 0;
    #5 lfsr_load = 32'hB0081355;
    
    #200 $finish;
  end
endmodule
