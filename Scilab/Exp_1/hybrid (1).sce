// =====================================================
// HYBRID TOPOLOGY : BUS + RING + TREE
// =====================================================

clear;
clc;

// =====================================================
// BUS TOPOLOGY (Nodes 1–8)
// =====================================================
bStart = [1 2 3 4 5 6 7];
bEnd   = [2 3 4 5 6 7 8];

xBus = [100 150 200 250 300 350 400 450];
yBus = [480 480 480 480 480 480 480 480];

// =====================================================
// RING TOPOLOGY (Nodes 9–16)
// =====================================================
rStart = [9 10 11 12 13 14 15 16];
rEnd   = [10 11 12 13 14 15 16 9];

angle = 0:%pi/4:(7*%pi/4);
xRing = 300 + 100*cos(angle);
yRing = 280 + 100*sin(angle);

// =====================================================
// TREE TOPOLOGY (Nodes 17–25)
// =====================================================
tStart = [17 17 18 18 19 19 20 20];
tEnd   = [18 19 20 21 22 23 24 25];

xTree = [500 480 520 460 540 440 560 420 580];
yTree = [500 450 450 400 400 350 350 300 300];

// =====================================================
// HYBRID LINKS
// =====================================================
bridgeStart = [4 12];
bridgeEnd   = [9 17];

// =====================================================
// MERGE ALL
// =====================================================
startAll = [bStart rStart tStart bridgeStart];
endAll   = [bEnd   rEnd   tEnd   bridgeEnd];

xAll = [xBus xRing xTree];
yAll = [yBus yRing yTree];

nodesTotal = 25;
edgesTotal = length(startAll);

// =====================================================
// CREATE GRAPH USING NARVAL
// =====================================================
TopologyGraph = NL_G_MakeGraph( ...
    "Hybrid Topology", ...
    nodesTotal, ...
    startAll, ...
    endAll, ...
    xAll, ...
    yAll ...
);

// =====================================================
// MANUAL DISPLAY
// =====================================================
scf(1);
clf();

// ---- Draw edges (black) ----
for i = 1:edgesTotal
    xpoly([xAll(startAll(i)) xAll(endAll(i))], ...
          [yAll(startAll(i)) yAll(endAll(i))], "lines");
end

// ---- Draw nodes (red circles) ----
plot(xAll, yAll, 'ro');
h = gce();
h.children.mark_size = 10;
h.children.thickness = 2;

// =====================================================
// NODE LABELS (N1, N2, …)
// =====================================================
for i = 1:nodesTotal
    xstring(xAll(i)+8, yAll(i)+8, "N"+string(i));
end

// =====================================================
// EDGE LABELS (E1, E2, …)
// =====================================================
for i = 1:edgesTotal
    xm = (xAll(startAll(i)) + xAll(endAll(i))) / 2;
    ym = (yAll(startAll(i)) + yAll(endAll(i))) / 2;
    xstring(xm, ym, "E"+string(i));
end

xtitle("Hybrid Topology: Bus + Ring + Tree", "X", "Y");

// =====================================================
// AXIS ZOOM
// =====================================================
a = gca();
a.data_bounds = [50 150; 650 550];
a.isoview = "on";

// =====================================================
// DEGREE CALCULATION
// =====================================================
degree = zeros(1, nodesTotal);

for i = 1:edgesTotal
    degree(startAll(i)) = degree(startAll(i)) + 1;
    degree(endAll(i))   = degree(endAll(i)) + 1;
end

disp("Number of edges connected to each node:");
for i = 1:nodesTotal
    disp("Node " + string(i) + " : " + string(degree(i)));
end

[maxDeg, maxNode] = max(degree);
disp("Node with maximum edges: Node " + string(maxNode));
disp("Maximum number of edges: " + string(maxDeg));

disp("Total number of nodes: " + string(nodesTotal));
disp("Total number of edges: " + string(edgesTotal));
