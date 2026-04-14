clc; clear;

//	PARAMETERS L = 1000;
flows = 60;
runs = 1;

// Node sizes
node_sizes = [500 400 300 200 100];

// Controlled density values dmax_values = [80 120 160 200 250];

num_methods = length(dmax_values); num_sizes = length(node_sizes);

results = zeros(num_methods, num_sizes);
 
// ---------------- CONGESTION SIMULATION FUNCTION ----------------
function t = simulate_congestion(g, flows) n_nodes = length(g.node_x); timer();
for k = 1:flows

src = grand(1,1,"uin",1,n_nodes); dst = grand(1,1,"uin",1,n_nodes);

if src <> dst then
[dist, pred] = NL_R_Dijkstra(g, src); end

end

t = timer(); endfunction


for m = 1:num_methods
dmax = dmax_values(m); disp(" ");
disp("Starting Method " + string(m) + ...
" (dmax = " + string(dmax) + ")"); for s = 1:num_sizes
n = node_sizes(s);

g = NL_T_LocalityConnex(n, L, dmax); results(m, s) = simulate_congestion(g, flows); disp("Completed: Nodes = " + string(n));
 
end
end


//	PLOT RESULTS
scf(1); clf();

for m = 1:num_methods
plot(node_sizes,  results(m,:),  'o-');
end

legend("Method 1 (dmax=80)", "Method 2 (dmax=120)", "Method 3 (dmax=160)",
"Method 4 (dmax=200)", "Method 5 (dmax=250)");

xtitle("Congestion Time for 5 Topology Methods", "Number of Nodes", "Time (seconds)");


//	DISPLAY RESULTS
disp(" ");
disp("Congestion Time Matrix (Rows=Methods, Columns=Node Sizes)"); disp("Node Sizes: 500 400 300 200 100");
disp(results);

